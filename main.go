package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const (
	vmName = "NP2-Pruebas"
	addr   = "127.0.0.1:8080"
)

var (
	tpl          *template.Template
	packageRegex  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	hostnameRegex = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	serviceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+\.service$`)
	backendNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)
	serverNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)

	sshMu          sync.RWMutex
	rootKeyHost    string
	rootTargetIP   string
	userKeyHost    = map[string]string{}
)

type PageData struct {
	Title          string
	VMName         string
	VMIP           string
	Environment    string
	Message        string
	Success        bool
	Technical      string
	Package        string
	SSHReady       bool
	RootTargetIP   string
	UserKeyReady   bool
	UserKeyName    string
	Users          []string
	ServiceName    string
	HAProxyIP      string
	BackendName    string
}

func baseData(title string) PageData {
	sshMu.RLock()
	defer sshMu.RUnlock()

	d := PageData{
		Title:       title,
		VMName:      vmName,
		VMIP:        "Comunicación inicial: Guest Additions",
		Environment: "Host Windows + VirtualBox",
		SSHReady:    rootKeyHost != "",
		RootTargetIP: rootTargetIP,
	}
	if d.SSHReady {
		d.VMIP = "Llave SSH de root configurada"
	}
	return d
}

func render(w http.ResponseWriter, name string, d PageData) {
	if err := tpl.ExecuteTemplate(w, name, d); err != nil {
		http.Error(w, "Error al renderizar: "+err.Error(), http.StatusInternalServerError)
	}
}

func runGuestCommand(rootPassword string, shellCommand string, successMarker string) (string, error) {
	if strings.TrimSpace(rootPassword) == "" {
		return "", fmt.Errorf("la contraseña de root es obligatoria")
	}

	tmp, err := os.CreateTemp("", "np2-root-*.txt")
	if err != nil {
		return "", fmt.Errorf("no se pudo crear el archivo temporal de credenciales: %w", err)
	}
	passwordFile := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(passwordFile)
	}()

	if _, err := tmp.WriteString(rootPassword); err != nil {
		return "", fmt.Errorf("no se pudo escribir la credencial temporal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("no se pudo cerrar el archivo temporal: %w", err)
	}

	args := []string{
		"guestcontrol", vmName, "run",
		"--username", "root",
		"--passwordfile", passwordFile,
		"--exe", "/bin/sh",
		"--wait-stdout",
		"--wait-stderr",
		"--",
		"-c", shellCommand,
	}

	cmd := exec.Command("VBoxManage", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	technical := strings.TrimSpace(stdout.String())
	if s := strings.TrimSpace(stderr.String()); s != "" {
		if technical != "" {
			technical += "\n"
		}
		technical += s
	}

	// La operación se considera exitosa solamente si el comando invitado
	// alcanzó la verificación final y escribió el marcador esperado.
	if successMarker != "" && strings.Contains(technical, successMarker) {
		technical = strings.ReplaceAll(technical, successMarker, "")
		return strings.TrimSpace(technical), nil
	}

	if err != nil {
		if technical == "" {
			technical = err.Error()
		}
		return technical, fmt.Errorf("la operación no terminó correctamente")
	}

	if successMarker != "" {
		return technical, fmt.Errorf("la operación terminó, pero no pudo verificarse el estado final")
	}

	return technical, nil
}


func makePasswordFile(rootPassword string) (string, func(), error) {
	if strings.TrimSpace(rootPassword) == "" {
		return "", nil, fmt.Errorf("la contraseña de root es obligatoria")
	}

	tmp, err := os.CreateTemp("", "np2-root-*.txt")
	if err != nil {
		return "", nil, err
	}
	name := tmp.Name()

	if _, err := tmp.WriteString(rootPassword); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", nil, err
	}

	cleanup := func() { _ = os.Remove(name) }
	return name, cleanup, nil
}

func copyFromGuest(passwordFile, guestSource, hostDestination string) (string, error) {
	cmd := exec.Command(
		"VBoxManage",
		"guestcontrol", vmName, "copyfrom",
		"--username", "root",
		"--passwordfile", passwordFile,
		guestSource,
		hostDestination,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	out := strings.TrimSpace(stdout.String())
	if s := strings.TrimSpace(stderr.String()); s != "" {
		if out != "" {
			out += "\n"
		}
		out += s
	}
	return out, err
}

func restrictWindowsPrivateKey(path string) string {
	userName := os.Getenv("USERNAME")
	if userName == "" {
		return "No se pudo determinar USERNAME para ajustar permisos NTFS."
	}

	var notes []string
	for _, args := range [][]string{
		{path, "/inheritance:r"},
		{path, "/grant:r", userName + ":R"},
	} {
		cmd := exec.Command("icacls", args...)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			notes = append(notes, strings.TrimSpace(string(out)))
		}
		if err != nil {
			notes = append(notes, "Advertencia al ajustar ACL: "+err.Error())
		}
	}
	return strings.Join(notes, "\n")
}

func generateRootSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/preparacion", http.StatusSeeOther)
		return
	}

	password := r.FormValue("root_password")
	data := baseData("Preparación del sistema")

	marker := "__NP2_SSH_ROOT_OK__"
	command := `set -e
install -d -m 700 /root/.ssh
rm -f /root/.ssh/id_ed25519 /root/.ssh/id_ed25519.pub
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 -C 'root@np2-pruebas'
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
PUB="$(cat /root/.ssh/id_ed25519.pub)"
grep -qxF "$PUB" /root/.ssh/authorized_keys || printf '%s\n' "$PUB" >> /root/.ssh/authorized_keys
cat >/etc/ssh/sshd_config.d/99-np2-root-key.conf <<'EOF'
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
/usr/sbin/sshd -t
systemctl reload ssh
hostname -I | awk '{print $1}'
echo ` + marker

	output, err := runGuestCommand(password, command, marker)
	if err != nil {
		data.Success = false
		data.Message = "No fue posible configurar las llaves SSH de root."
		data.Technical = output
		render(w, "preparacion.html", data)
		return
	}

	lines := strings.Fields(output)
	var ip string
	for _, f := range lines {
		if strings.Count(f, ".") == 3 {
			ip = f
		}
	}
	if ip == "" {
		data.Success = false
		data.Message = "La llave se generó, pero no fue posible identificar la IP de la VM."
		data.Technical = output
		render(w, "preparacion.html", data)
		return
	}

	passwordFile, cleanup, err := makePasswordFile(password)
	if err != nil {
		data.Success = false
		data.Message = "No fue posible preparar la descarga de la llave privada."
		data.Technical = err.Error()
		render(w, "preparacion.html", data)
		return
	}
	defer cleanup()

	keyDir := filepath.Join(os.TempDir(), "np2-automatizacion")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		data.Success = false
		data.Message = "No fue posible crear el directorio temporal de la llave privada."
		data.Technical = err.Error()
		render(w, "preparacion.html", data)
		return
	}
	hostKey := filepath.Join(keyDir, "np2-root-ed25519")
	_ = os.Remove(hostKey)

	copyOut, copyErr := copyFromGuest(passwordFile, "/root/.ssh/id_ed25519", hostKey)
	if copyErr != nil {
		data.Success = false
		data.Message = "Las llaves fueron creadas en Debian, pero no se pudo copiar la llave privada al host."
		data.Technical = output + "\n" + copyOut
		render(w, "preparacion.html", data)
		return
	}

	aclNotes := restrictWindowsPrivateKey(hostKey)

	sshMu.Lock()
	rootKeyHost = hostKey
	rootTargetIP = ip
	sshMu.Unlock()

	data = baseData("Preparación del sistema")
	data.Success = true
	data.Message = "Llaves SSH de root configuradas correctamente."
	data.Technical = strings.TrimSpace(output + "\n" + copyOut + "\n" + aclNotes)
	render(w, "preparacion.html", data)
}

func downloadRootKey(w http.ResponseWriter, r *http.Request) {
	sshMu.RLock()
	keyPath := rootKeyHost
	sshMu.RUnlock()

	if keyPath == "" {
		http.Error(w, "Todavía no se ha generado una llave privada para descargar.", http.StatusNotFound)
		return
	}

	if _, err := os.Stat(keyPath); err != nil {
		http.Error(w, "La llave privada ya no está disponible en el host.", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="np2-root-ed25519"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, keyPath)
}


func validIPv4(ip string) bool {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func runSSHCommand(ip, keyPath, remoteCommand string) (string, error) {
	ip = strings.TrimSpace(ip)
	keyPath = strings.TrimSpace(keyPath)

	if !validIPv4(ip) {
		return "", fmt.Errorf("dirección IP inválida")
	}
	if keyPath == "" {
		return "", fmt.Errorf("debe indicar la ruta de la llave privada")
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "", fmt.Errorf("no se encontró la llave privada en la ruta indicada")
	}

	args := []string{
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "BatchMode=yes",
		"root@" + ip,
		remoteCommand,
	}

	cmd := exec.Command("ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	out := strings.TrimSpace(stdout.String())
	if s := strings.TrimSpace(stderr.String()); s != "" {
		if out != "" {
			out += "\n"
		}
		out += s
	}
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return out, fmt.Errorf("falló la ejecución remota por SSH")
	}
	return out, nil
}

func configureIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/preparacion", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	message := strings.TrimSpace(r.FormValue("issue_message"))

	var lines []string
	lines = append(lines, `Debian GNU/Linux 13 \l`)

	if r.FormValue("show_hostname") == "on" {
		lines = append(lines, `Hostname: \n`)
	}
	if r.FormValue("show_date") == "on" {
		lines = append(lines, `Fecha: \d`)
	}
	if r.FormValue("show_time") == "on" {
		lines = append(lines, `Hora: \t`)
	}
	if r.FormValue("show_ip") == "on" {
		lines = append(lines, `IP Address: \4`)
	}
	if message != "" {
		lines = append(lines, "Mensaje: "+message)
	}

	content := strings.Join(lines, "\n") + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	remote := fmt.Sprintf(
		`printf '%%s' '%s' | base64 -d > /etc/issue && echo '--- /etc/issue guardado ---' && cat /etc/issue`,
		encoded,
	)

	data := baseData("Preparación del sistema")
	data.RootTargetIP = ip

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Success = false
		data.Message = "No fue posible actualizar /etc/issue mediante SSH."
		data.Technical = out
		render(w, "preparacion.html", data)
		return
	}

	data.Success = true
	data.Message = "Entrada del sistema (/etc/issue) actualizada correctamente por SSH."
	data.Technical = out
	render(w, "preparacion.html", data)
}


func configureHostname(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/preparacion", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	newHost := strings.ToLower(strings.TrimSpace(r.FormValue("new_hostname")))

	data := baseData("Preparación del sistema")
	data.RootTargetIP = ip

	if !hostnameRegex.MatchString(newHost) {
		data.Success = false
		data.Message = "Nombre de host inválido."
		data.Technical = "Use letras minúsculas, números y guiones. No inicie ni termine con guion y use máximo 63 caracteres."
		render(w, "preparacion.html", data)
		return
	}

	// Encode hostname to safely embed it in the remote shell.
	hostB64 := base64.StdEncoding.EncodeToString([]byte(newHost))

	remote := fmt.Sprintf(
		`set -e
NEW_HOST="$(printf '%%s' '%s' | base64 -d)"
hostnamectl set-hostname "$NEW_HOST"
if grep -qE '^127\.0\.1\.1[[:space:]]+' /etc/hosts; then
  sed -i -E "s/^127\.0\.1\.1[[:space:]]+.*/127.0.1.1\t$NEW_HOST/" /etc/hosts
else
  printf '127.0.1.1\t%%s\n' "$NEW_HOST" >> /etc/hosts
fi
echo "--- hostname ---"
hostname
echo "--- /etc/hosts ---"
grep -E '^(127\.0\.0\.1|127\.0\.1\.1)' /etc/hosts`,
		hostB64,
	)

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Success = false
		data.Message = "No fue posible cambiar el hostname mediante SSH."
		data.Technical = out
		render(w, "preparacion.html", data)
		return
	}

	if !strings.Contains(out, newHost) {
		data.Success = false
		data.Message = "La operación terminó, pero no pudo verificarse el nuevo hostname."
		data.Technical = out
		render(w, "preparacion.html", data)
		return
	}

	data.Success = true
	data.Message = "Hostname y archivo /etc/hosts actualizados correctamente."
	data.Technical = out
	render(w, "preparacion.html", data)
}



func loadUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/usuarios", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))

	data := baseData("Gestión de usuarios")

	remote := `awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd | sort`

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible consultar los usuarios de la máquina virtual."
		data.Technical = out
		render(w, "usuarios.html", data)
		return
	}

	var users []string
	for _, u := range strings.Fields(out) {
		u = strings.TrimSpace(u)
		if u == "" || u == "root" || u == "andres" {
			continue
		}
		if usernameRegex.MatchString(u) {
			users = append(users, u)
		}
	}

	data.Success = true
	data.Users = users
	if len(users) == 0 {
		data.Message = "Consulta realizada correctamente. No hay usuarios eliminables disponibles."
	} else {
		data.Message = fmt.Sprintf("Usuarios cargados correctamente: %d disponible(s).", len(users))
	}
	render(w, "usuarios.html", data)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/usuarios", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("user_password")
	withSudo := r.FormValue("with_sudo") == "on"
	withSSH := r.FormValue("with_ssh") == "on"

	data := baseData("Gestión de usuarios")

	if !usernameRegex.MatchString(username) {
		data.Message = "Nombre de usuario inválido."
		data.Technical = "Use letras minúsculas, números, guion o guion bajo. Máximo 32 caracteres."
		render(w, "usuarios.html", data)
		return
	}
	if username == "root" || username == "andres" {
		data.Message = "Ese usuario está protegido para evitar afectar el entorno de administración."
		render(w, "usuarios.html", data)
		return
	}
	if password == "" && !withSSH {
		data.Message = "Debe indicar una contraseña o habilitar la generación de llave SSH."
		render(w, "usuarios.html", data)
		return
	}

	userB64 := base64.StdEncoding.EncodeToString([]byte(username))
	passB64 := base64.StdEncoding.EncodeToString([]byte(password))

	script := `set -e
USER_NAME="$(printf '%s' '` + userB64 + `' | base64 -d)"
USER_PASS="$(printf '%s' '` + passB64 + `' | base64 -d)"
if id "$USER_NAME" >/dev/null 2>&1; then
  echo "ERROR: el usuario ya existe"
  exit 10
fi
useradd -m -s /bin/bash "$USER_NAME"
`
	if password != "" {
		script += `printf '%s:%s\n' "$USER_NAME" "$USER_PASS" | chpasswd
`
	}
	if withSudo {
		script += `usermod -aG sudo "$USER_NAME"
`
	}
	if withSSH {
		script += `install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
ssh-keygen -q -t ed25519 -N '' -f "/home/$USER_NAME/.ssh/id_ed25519" -C "$USER_NAME@np2"
cp "/home/$USER_NAME/.ssh/id_ed25519.pub" "/home/$USER_NAME/.ssh/authorized_keys"
chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh"
chmod 700 "/home/$USER_NAME/.ssh"
chmod 600 "/home/$USER_NAME/.ssh/authorized_keys" "/home/$USER_NAME/.ssh/id_ed25519"
chmod 644 "/home/$USER_NAME/.ssh/id_ed25519.pub"
cat >"/etc/ssh/sshd_config.d/99-np2-user-$USER_NAME.conf" <<EOF
Match User $USER_NAME
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
EOF
/usr/sbin/sshd -t
systemctl reload ssh
`
	}
	script += `echo "--- usuario creado ---"
id "$USER_NAME"
echo "--- grupos ---"
groups "$USER_NAME"
`

	out, err := runSSHCommand(ip, keyPath, script)
	if err != nil {
		data.Message = "No fue posible crear el usuario."
		data.Technical = out
		render(w, "usuarios.html", data)
		return
	}

	if withSSH {
		keyDir := filepath.Join(os.TempDir(), "np2-automatizacion", "users")
		_ = os.MkdirAll(keyDir, 0700)
		hostKey := filepath.Join(keyDir, "np2-"+username+"-ed25519")
		_ = os.Remove(hostKey)

		remoteKey := fmt.Sprintf("root@%s:/home/%s/.ssh/id_ed25519", ip, username)
		cmd := exec.Command("scp",
			"-i", keyPath,
			"-o", "IdentitiesOnly=yes",
			"-o", "StrictHostKeyChecking=accept-new",
			remoteKey, hostKey,
		)
		copyOut, copyErr := cmd.CombinedOutput()
		if copyErr != nil {
			data.Message = "El usuario fue creado, pero no se pudo copiar la llave privada al host."
			data.Technical = out + "\n" + string(copyOut)
			render(w, "usuarios.html", data)
			return
		}

		_ = restrictWindowsPrivateKey(hostKey)
		sshMu.Lock()
		userKeyHost[username] = hostKey
		sshMu.Unlock()

		data.UserKeyReady = true
		data.UserKeyName = username
	}

	data.Success = true
	data.Message = "Usuario creado correctamente."
	data.Technical = out
	render(w, "usuarios.html", data)
}

func downloadUserKey(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if !usernameRegex.MatchString(username) {
		http.Error(w, "Usuario inválido", http.StatusBadRequest)
		return
	}

	sshMu.RLock()
	keyPath := userKeyHost[username]
	sshMu.RUnlock()

	if keyPath == "" {
		http.Error(w, "No hay una llave privada disponible para ese usuario.", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(keyPath); err != nil {
		http.Error(w, "La llave privada ya no está disponible.", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="np2-%s-ed25519"`, username))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, keyPath)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/usuarios", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username_delete")))
	removeFiles := r.FormValue("remove_files") == "on"

	data := baseData("Gestión de usuarios")

	if !usernameRegex.MatchString(username) {
		data.Message = "Nombre de usuario inválido."
		render(w, "usuarios.html", data)
		return
	}
	if username == "root" || username == "andres" {
		data.Message = "Ese usuario está protegido y no puede eliminarse desde la consola."
		render(w, "usuarios.html", data)
		return
	}

	userB64 := base64.StdEncoding.EncodeToString([]byte(username))
	removeFlag := ""
	if removeFiles {
		removeFlag = "-r"
	}

	remote := fmt.Sprintf(
		`set -e
USER_NAME="$(printf '%%s' '%s' | base64 -d)"
if ! id "$USER_NAME" >/dev/null 2>&1; then
  echo "ERROR: el usuario no existe"
  exit 11
fi
userdel %s "$USER_NAME"
rm -f "/etc/ssh/sshd_config.d/99-np2-user-$USER_NAME.conf"
if /usr/sbin/sshd -t; then
  systemctl reload ssh
fi
echo "--- usuario eliminado ---"
if id "$USER_NAME" >/dev/null 2>&1; then
  echo "ERROR: el usuario continúa existiendo"
  exit 12
else
  echo "Verificación: el usuario ya no existe."
fi`,
		userB64, removeFlag,
	)

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible eliminar el usuario."
		data.Technical = out
		render(w, "usuarios.html", data)
		return
	}

	sshMu.Lock()
	delete(userKeyHost, username)
	sshMu.Unlock()

	data.Success = true
	if removeFiles {
		data.Message = "Usuario y archivos eliminados correctamente."
	} else {
		data.Message = "Usuario eliminado correctamente; su directorio personal se conservó."
	}
	data.Technical = out
	render(w, "usuarios.html", data)
}


func prepareTestService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/servicios", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))

	scriptContent := `#!/bin/bash
FECHA="$(date '+%Y-%m-%d %H:%M:%S')"
echo "$FECHA - Servicio NP2 ejecutado correctamente" >> /var/log/np2-fecha.log
`
	serviceContent := `[Unit]
Description=Servicio de prueba NP2 - registro de fecha y hora
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/np2-fecha.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

	scriptB64 := base64.StdEncoding.EncodeToString([]byte(scriptContent))
	serviceB64 := base64.StdEncoding.EncodeToString([]byte(serviceContent))

	remote := fmt.Sprintf(
		`set -e
printf '%%s' '%s' | base64 -d > /usr/local/bin/np2-fecha.sh
chmod 755 /usr/local/bin/np2-fecha.sh
printf '%%s' '%s' | base64 -d > /etc/systemd/system/np2-fecha.service
chmod 644 /etc/systemd/system/np2-fecha.service
systemctl daemon-reload
echo "--- script ---"
ls -l /usr/local/bin/np2-fecha.sh
echo "--- servicio ---"
systemctl cat np2-fecha.service`,
		scriptB64, serviceB64,
	)

	data := baseData("Gestión de servicios")
	data.ServiceName = "np2-fecha.service"

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible preparar el servicio de prueba."
		data.Technical = out
		render(w, "servicios.html", data)
		return
	}

	data.Success = true
	data.Message = "Servicio de prueba np2-fecha.service preparado correctamente."
	data.Technical = out
	render(w, "servicios.html", data)
}

func systemdAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/servicios", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ssh_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	service := strings.TrimSpace(r.FormValue("service_name"))
	action := strings.TrimSpace(r.FormValue("action"))

	data := baseData("Gestión de servicios")
	data.ServiceName = service

	if !serviceRegex.MatchString(service) {
		data.Message = "Nombre de servicio inválido."
		data.Technical = "Ejemplo válido: np2-fecha.service"
		render(w, "servicios.html", data)
		return
	}

	allowed := map[string]bool{
		"start": true, "stop": true, "restart": true,
		"status": true, "enable": true, "disable": true,
	}
	if !allowed[action] {
		data.Message = "Acción systemd no permitida."
		render(w, "servicios.html", data)
		return
	}

	var remote string
	if action == "status" {
		remote = fmt.Sprintf(
			`systemctl status %s --no-pager --full || true
echo "--- enabled ---"
systemctl is-enabled %s 2>/dev/null || true
echo "--- active ---"
systemctl is-active %s 2>/dev/null || true
echo "--- log de prueba ---"
tail -n 10 /var/log/np2-fecha.log 2>/dev/null || echo "Todavía no existe /var/log/np2-fecha.log"`,
			service, service, service,
		)
	} else {
		remote = fmt.Sprintf(
			`set -e
systemctl %s %s
echo "--- resultado ---"
echo "Acción: %s"
echo "Servicio: %s"
echo "Estado activo:"
systemctl is-active %s 2>/dev/null || true
echo "Habilitado al arranque:"
systemctl is-enabled %s 2>/dev/null || true
echo "--- últimas ejecuciones del script ---"
tail -n 10 /var/log/np2-fecha.log 2>/dev/null || echo "Todavía no existe /var/log/np2-fecha.log"`,
			action, service, action, service, service, service,
		)
	}

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible ejecutar la acción sobre el servicio."
		data.Technical = out
		render(w, "servicios.html", data)
		return
	}

	data.Success = true
	if action == "status" {
		data.Message = "Estado del servicio consultado correctamente."
	} else {
		data.Message = "Acción " + action + " ejecutada correctamente."
	}
	data.Technical = out
	render(w, "servicios.html", data)
}


func validPort(p string) bool {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err != nil {
		return false
	}
	return n >= 1 && n <= 65535
}

func haproxyAddServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/haproxy", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("haproxy_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	backend := strings.TrimSpace(r.FormValue("backend_name"))
	server := strings.TrimSpace(r.FormValue("server_name"))
	serverIP := strings.TrimSpace(r.FormValue("server_ip"))
	port := strings.TrimSpace(r.FormValue("server_port"))

	data := baseData("Gestión de HAProxy")
	data.HAProxyIP = ip
	data.BackendName = backend

	if !validIPv4(ip) {
		data.Message = "La IP de NP2-HAProxy no es válida."
		render(w, "haproxy.html", data)
		return
	}
	if !backendNameRegex.MatchString(backend) || !serverNameRegex.MatchString(server) {
		data.Message = "Nombre de backend o servidor inválido."
		render(w, "haproxy.html", data)
		return
	}
	if !validIPv4(serverIP) || !validPort(port) {
		data.Message = "La IP o el puerto del servidor backend no son válidos."
		render(w, "haproxy.html", data)
		return
	}

	backendB64 := base64.StdEncoding.EncodeToString([]byte(backend))
	serverB64 := base64.StdEncoding.EncodeToString([]byte(server))
	serverIPB64 := base64.StdEncoding.EncodeToString([]byte(serverIP))
	portB64 := base64.StdEncoding.EncodeToString([]byte(port))

	remote := fmt.Sprintf(
		`set -e
CFG="/etc/haproxy/haproxy.cfg"
BACKEND="$(printf '%%s' '%s' | base64 -d)"
SERVER="$(printf '%%s' '%s' | base64 -d)"
SERVER_IP="$(printf '%%s' '%s' | base64 -d)"
SERVER_PORT="$(printf '%%s' '%s' | base64 -d)"
BEGIN="# BEGIN NP2 BACKEND $BACKEND"
END="# END NP2 BACKEND $BACKEND"
cp "$CFG" "$CFG.np2.bak"

if grep -qF "$BEGIN" "$CFG"; then
  if awk -v b="$BEGIN" -v e="$END" -v s="$SERVER" '
    $0==b {inside=1; next}
    $0==e {inside=0}
    inside && $1=="server" && $2==s {found=1}
    END {exit(found?0:1)}
  ' "$CFG"; then
    echo "ERROR: ya existe un servidor con ese nombre en el backend"
    exit 21
  fi

  awk -v e="$END" -v line="    server $SERVER $SERVER_IP:$SERVER_PORT check" '
    $0==e {print line}
    {print}
  ' "$CFG" > "$CFG.tmp"
  mv "$CFG.tmp" "$CFG"
else
  {
    echo ""
    echo "$BEGIN"
    echo "backend $BACKEND"
    echo "    balance roundrobin"
    echo "    server $SERVER $SERVER_IP:$SERVER_PORT check"
    echo "$END"
  } >> "$CFG"
fi

if ! /usr/sbin/haproxy -c -f "$CFG"; then
  cp "$CFG.np2.bak" "$CFG"
  echo "ERROR: configuración inválida, se restauró la copia"
  exit 22
fi

systemctl reload haproxy

echo "--- configuración válida ---"
/usr/sbin/haproxy -c -f "$CFG"
echo "--- backend administrado ---"
awk -v b="$BEGIN" -v e="$END" '
  $0==b {inside=1}
  inside {print}
  $0==e {inside=0}
' "$CFG"
echo "--- servicio HAProxy ---"
systemctl is-active haproxy`,
		backendB64, serverB64, serverIPB64, portB64,
	)

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible agregar el servidor al backend."
		data.Technical = out
		render(w, "haproxy.html", data)
		return
	}

	data.Success = true
	data.Message = "Servidor agregado al backend y HAProxy recargado correctamente."
	data.Technical = out
	render(w, "haproxy.html", data)
}

func haproxyRemoveServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/haproxy", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("haproxy_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	backend := strings.TrimSpace(r.FormValue("backend_name"))
	server := strings.TrimSpace(r.FormValue("server_name"))

	data := baseData("Gestión de HAProxy")
	data.HAProxyIP = ip
	data.BackendName = backend

	if !validIPv4(ip) || !backendNameRegex.MatchString(backend) || !serverNameRegex.MatchString(server) {
		data.Message = "Datos inválidos para eliminar el servidor."
		render(w, "haproxy.html", data)
		return
	}

	backendB64 := base64.StdEncoding.EncodeToString([]byte(backend))
	serverB64 := base64.StdEncoding.EncodeToString([]byte(server))

	remote := fmt.Sprintf(
		`set -e
CFG="/etc/haproxy/haproxy.cfg"
BACKEND="$(printf '%%s' '%s' | base64 -d)"
SERVER="$(printf '%%s' '%s' | base64 -d)"
BEGIN="# BEGIN NP2 BACKEND $BACKEND"
END="# END NP2 BACKEND $BACKEND"

if ! grep -qF "$BEGIN" "$CFG"; then
  echo "ERROR: el backend administrado no existe"
  exit 31
fi

if ! awk -v b="$BEGIN" -v e="$END" -v s="$SERVER" '
  $0==b {inside=1; next}
  $0==e {inside=0}
  inside && $1=="server" && $2==s {found=1}
  END {exit(found?0:1)}
' "$CFG"; then
  echo "ERROR: no existe ese servidor dentro del backend"
  exit 32
fi

cp "$CFG" "$CFG.np2.bak"

awk -v b="$BEGIN" -v e="$END" -v s="$SERVER" '
  $0==b {inside=1}
  $0==e {inside=0}
  inside && $1=="server" && $2==s {next}
  {print}
' "$CFG" > "$CFG.tmp"
mv "$CFG.tmp" "$CFG"

if ! /usr/sbin/haproxy -c -f "$CFG"; then
  cp "$CFG.np2.bak" "$CFG"
  echo "ERROR: configuración inválida, se restauró la copia"
  exit 33
fi

systemctl reload haproxy

echo "--- servidor eliminado ---"
echo "$SERVER"
echo "--- backend administrado ---"
awk -v b="$BEGIN" -v e="$END" '
  $0==b {inside=1}
  inside {print}
  $0==e {inside=0}
' "$CFG"
echo "--- servicio HAProxy ---"
systemctl is-active haproxy`,
		backendB64, serverB64,
	)

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible eliminar el servidor del backend."
		data.Technical = out
		render(w, "haproxy.html", data)
		return
	}

	data.Success = true
	data.Message = "Servidor eliminado del backend y HAProxy recargado correctamente."
	data.Technical = out
	render(w, "haproxy.html", data)
}

func haproxyShowBackend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/haproxy", http.StatusSeeOther)
		return
	}

	ip := strings.TrimSpace(r.FormValue("haproxy_ip"))
	keyPath := strings.TrimSpace(r.FormValue("ssh_key"))
	backend := strings.TrimSpace(r.FormValue("backend_name"))

	data := baseData("Gestión de HAProxy")
	data.HAProxyIP = ip
	data.BackendName = backend

	if !validIPv4(ip) || !backendNameRegex.MatchString(backend) {
		data.Message = "Datos de conexión/backend inválidos."
		render(w, "haproxy.html", data)
		return
	}

	backendB64 := base64.StdEncoding.EncodeToString([]byte(backend))
	remote := fmt.Sprintf(
		`CFG="/etc/haproxy/haproxy.cfg"
BACKEND="$(printf '%%s' '%s' | base64 -d)"
BEGIN="# BEGIN NP2 BACKEND $BACKEND"
END="# END NP2 BACKEND $BACKEND"
echo "--- validación HAProxy ---"
/usr/sbin/haproxy -c -f "$CFG"
echo "--- backend administrado ---"
if grep -qF "$BEGIN" "$CFG"; then
  awk -v b="$BEGIN" -v e="$END" '
    $0==b {inside=1}
    inside {print}
    $0==e {inside=0}
  ' "$CFG"
else
  echo "Aún no existe un backend administrado con ese nombre."
fi
echo "--- servicio ---"
systemctl is-active haproxy`,
		backendB64,
	)

	out, err := runSSHCommand(ip, keyPath, remote)
	if err != nil {
		data.Message = "No fue posible consultar HAProxy."
		data.Technical = out
		render(w, "haproxy.html", data)
		return
	}

	data.Success = true
	data.Message = "Configuración de HAProxy consultada correctamente."
	data.Technical = out
	render(w, "haproxy.html", data)
}

func packageAction(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/preparacion", http.StatusSeeOther)
		return
	}

	pkg := strings.ToLower(strings.TrimSpace(r.FormValue("package")))
	password := r.FormValue("root_password")

	data := baseData("Preparación del sistema")
	data.Package = pkg

	if !packageRegex.MatchString(pkg) {
		data.Message = "Nombre de paquete inválido. Use solamente letras minúsculas, números y los caracteres + . -"
		data.Technical = "Validación local: el nombre no cumple el formato permitido para paquetes Debian."
		render(w, "preparacion.html", data)
		return
	}

	var command, friendly, marker string

	switch action {
	case "install":
		marker = "__NP2_INSTALL_OK__"
		command = fmt.Sprintf(
			`export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y %s && dpkg-query -W -f='${Status} ${Version}
' %s | grep -q '^install ok installed' && echo %s`,
			pkg, pkg, marker,
		)
		friendly = "Paquete instalado y verificado correctamente."

	case "remove":
		marker = "__NP2_REMOVE_OK__"
		command = fmt.Sprintf(
			`export DEBIAN_FRONTEND=noninteractive; apt-get remove -y %s && if dpkg-query -W -f='${Status}
' %s 2>/dev/null | grep -q '^install ok installed'; then echo "ERROR: el paquete continúa instalado"; exit 1; else echo "Verificación: el paquete ya no está instalado."; echo %s; fi`,
			pkg, pkg, marker,
		)
		friendly = "Paquete eliminado y verificado correctamente."

	default:
		http.Error(w, "Acción no válida", http.StatusBadRequest)
		return
	}

	output, err := runGuestCommand(password, command, marker)
	if err != nil {
		data.Success = false
		data.Message = "No fue posible completar la operación."
		data.Technical = output
		if strings.Contains(strings.ToLower(output), "password") ||
			strings.Contains(strings.ToLower(output), "authentication") {
			data.Message = "No se pudo autenticar en la máquina virtual. Revise la contraseña de root."
		}
		render(w, "preparacion.html", data)
		return
	}

	data.Success = true
	data.Message = friendly
	if strings.TrimSpace(output) == "" {
		output = "La operación terminó sin salida adicional."
	}
	data.Technical = output
	render(w, "preparacion.html", data)
}

func main() {
	var err error
	tpl, err = template.ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, "index.html", baseData("Consola de automatización de servicios"))
	})

	http.HandleFunc("/preparacion", func(w http.ResponseWriter, r *http.Request) {
		render(w, "preparacion.html", baseData("Preparación del sistema"))
	})

	http.HandleFunc("/preparacion/install", func(w http.ResponseWriter, r *http.Request) {
		packageAction(w, r, "install")
	})

	http.HandleFunc("/preparacion/remove", func(w http.ResponseWriter, r *http.Request) {
		packageAction(w, r, "remove")
	})

	http.HandleFunc("/preparacion/ssh/generate", generateRootSSH)
	http.HandleFunc("/preparacion/ssh/download", downloadRootKey)
	http.HandleFunc("/preparacion/issue", configureIssue)
	http.HandleFunc("/preparacion/hostname", configureHostname)

	http.HandleFunc("/usuarios", func(w http.ResponseWriter, r *http.Request) {
		render(w, "usuarios.html", baseData("Gestión de usuarios"))
	})
	http.HandleFunc("/usuarios/create", createUser)
	http.HandleFunc("/usuarios/delete", deleteUser)
	http.HandleFunc("/usuarios/load", loadUsers)
	http.HandleFunc("/usuarios/key/download", downloadUserKey)

	http.HandleFunc("/servicios", func(w http.ResponseWriter, r *http.Request) {
		d := baseData("Gestión de servicios")
		d.ServiceName = "np2-fecha.service"
		render(w, "servicios.html", d)
	})
	http.HandleFunc("/servicios/prepare", prepareTestService)
	http.HandleFunc("/servicios/action", systemdAction)

	http.HandleFunc("/haproxy", func(w http.ResponseWriter, r *http.Request) {
		d := baseData("Gestión de HAProxy")
		d.BackendName = "np2_backend"
		render(w, "haproxy.html", d)
	})
	http.HandleFunc("/haproxy/add", haproxyAddServer)
	http.HandleFunc("/haproxy/remove", haproxyRemoveServer)
	http.HandleFunc("/haproxy/show", haproxyShowBackend)

	log.Printf("Consola disponible en http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
