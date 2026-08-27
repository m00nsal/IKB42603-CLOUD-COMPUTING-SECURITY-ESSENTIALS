# Lab 4: Access Control & Network Security

## Course Information

- **Course Name:** IKB42603 Cloud Computing Security Essentials
- **Instructor:** Madam Adani
- **Student Name:** SITI NUR SALIHAH BINTI AHMAD BALKIS
- **Topic:** Authentication, authorization, MFA, network segmentation, firewall rules and container hardening
- **Environment:** Kali Linux, Docker, Nginx, Kubernetes, Kind, kubectl, oathtool, iptables and Trivy
- **Date:** 27 August 2026

## Lab Objectives

The objectives of this lab are:

- To distinguish between authentication and authorization.
- To protect a web service using HTTP Basic Authentication.
- To generate and validate a TOTP code as a second authentication factor.
- To enforce least-privilege access using Kubernetes RBAC.
- To implement network segmentation between the web, application and database tiers.
- To configure default-deny firewall rules with explicit allowed traffic.
- To harden a container using non-root access, a read-only filesystem and restricted Linux capabilities.
- To scan a container image for known vulnerabilities using Trivy.

## Learning Outcomes

After completing this lab, I was able to:

- Configure a password-protected Nginx web service.
- Test unauthenticated and authenticated access using HTTP status codes.
- Generate and validate a six-digit TOTP code.
- Create a Kubernetes service account, role and role binding.
- Test allowed and denied actions using Kubernetes RBAC.
- Separate containers using frontend and backend Docker networks.
- Verify that the web tier could not directly reach the database tier.
- Configure a default-deny firewall policy using iptables.
- Run a hardened container as a non-root user with a read-only filesystem.
- Drop unnecessary Linux capabilities and prevent privilege escalation.
- Scan a container image for high and critical vulnerabilities using Trivy.

## Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux |
| Container Platform | Docker |
| Web Server | Nginx |
| Authentication Method | HTTP Basic Authentication |
| MFA Tool | oathtool |
| MFA Method | TOTP |
| Kubernetes Cluster Tool | Kind |
| Kubernetes Version | v1.30.0 |
| Kubernetes Command-Line Tool | kubectl |
| Access Control | Kubernetes RBAC |
| Network Segmentation | Docker networks |
| Database Service | Redis |
| Firewall Tool | iptables |
| Hardened Image | nginxinc/nginx-unprivileged |
| Vulnerability Scanner | Trivy |
| Working Directory | `~/Lab4` |

## Lab Summary

In this lab, an Nginx web service was protected using HTTP Basic Authentication, and a TOTP code was generated and validated as a second authentication factor. Kubernetes RBAC was configured to allow a developer service account to list pods while denying permission to create deployments and delete pods. Docker networks were used to separate the web, application and database tiers, preventing the web container from directly reaching the database. A default-deny firewall was also configured to allow only required traffic. Finally, a container was hardened using a non-root user, a read-only filesystem, dropped capabilities and the no-new-privileges option. The `nginx:alpine` image was then scanned using Trivy to identify known high and critical vulnerabilities.

## Step-by-Step Implementation

### Task 1: Authentication - Password-Protected Service

A password-protected Nginx web service was created to demonstrate HTTP Basic Authentication. First, a password file was generated for the user `student`.

```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt
```

A simple webpage was created to display a successful authentication message.

```bash
mkdir -p html
echo 'Authenticated OK' > html/index.html
```

The following authentication configuration was saved in `default.conf`.

```nginx
server {
    listen 80;

    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;

        root /usr/share/nginx/html;
        index index.html;
    }
}
```

The Nginx container was started on port `8080` with the configuration, password file and webpage mounted into the container.

```bash
docker run --rm -d --name authsvc -p 8080:80 \
  -v "$(pwd)/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$(pwd)/htpasswd.txt:/etc/nginx/.htpasswd:ro" \
  -v "$(pwd)/html:/usr/share/nginx/html:ro" \
  nginx
```

Access without credentials was tested.

```bash
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
```

The request returned:

```text
no-creds: 401
```

Access using the correct username and password was then tested.

```bash
curl -s -u student:'P@ssw0rd!' \
  -w '\nvalid-creds: %{http_code}\n' http://localhost:8080
```

The authenticated request returned:

```text
Authenticated OK
valid-creds: 200
```

The `401` response confirmed that access without credentials was rejected. The `200` response confirmed that the correct username and password successfully authenticated the user.

![HTTP Basic Authentication Test](Evidence/1-Basic-Authentication.png)

**Figure 1: HTTP Basic Authentication Test.** The request without credentials returned HTTP status code `401`. After the correct credentials were provided, the service displayed `Authenticated OK` and returned HTTP status code `200`.

---

### Task 2: Multi-Factor Authentication Using TOTP

A time-based one-time password was generated and validated to demonstrate a second authentication factor. First, a random Base32 shared secret was generated.

```bash
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol this secret in an authenticator app: $SECRET"
```

The shared secret was used to generate and store the current six-digit TOTP code.

```bash
CURRENT_CODE=$(oathtool --totp -b "$SECRET")
echo "Current TOTP code: $CURRENT_CODE"
```

Since Kali Linux uses Zsh as its default shell, the Zsh-compatible `read` command was used to request the code.

```bash
read "CODE?Enter the 6-digit code: "
```

The entered code was compared with the generated TOTP code.

```bash
[ "$CODE" = "$CURRENT_CODE" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

The system returned:

```text
MFA OK
```

This confirmed that the correct TOTP code was entered and successfully validated as a second authentication factor.

![TOTP MFA Validation](Evidence/2-MFA-TOTP-Validation.png)

**Figure 2: TOTP Multi-Factor Authentication Validation.** A shared secret and six-digit TOTP code were generated. The correct code was entered, and the `MFA OK` result confirmed successful validation.

---

### Task 3: Authorization Using Kubernetes RBAC

A Kubernetes cluster named `ccse-lab4` was created using Kind.

```bash
kind create cluster --name ccse-lab4
```

A namespace named `app` and a service account named `dev` were then created.

```bash
kubectl create namespace app
kubectl create serviceaccount dev -n app
```

A role named `dev-role` was created. This role only allowed the `get` and `list` actions on pods.

```bash
kubectl create role dev-role -n app \
  --verb=get,list \
  --resource=pods
```

The role was assigned to the `dev` service account using a role binding.

```bash
kubectl create rolebinding dev-rb -n app \
  --role=dev-role \
  --serviceaccount=app:dev
```

The service account identity was stored in a variable.

```bash
SA=system:serviceaccount:app:dev
```

The service account permissions were tested using three authorization checks.

```bash
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

The results were:

```text
yes
no
no
```

The `dev` service account was allowed to list pods but was not allowed to create deployments or delete pods. This demonstrated that Kubernetes RBAC successfully enforced least-privilege access.

![Kubernetes RBAC Authorization](Evidence/3-Kubernetes-RBAC-Authorization.png)

**Figure 3: Kubernetes RBAC Authorization Enforcement.** The `dev` service account was permitted to list pods but denied permission to create deployments and delete pods.

---

### Task 4: Three-Tier Network Segmentation

Two Docker networks were created to separate the frontend and backend tiers.

```bash
docker network create frontend-net
docker network create backend-net
```

A Redis database container was placed only in `backend-net`.

```bash
docker run -d --name db --network backend-net redis:alpine
```

The application container was initially placed in `backend-net`.

```bash
docker run -d --name app --network backend-net nginx
```

The application container was also connected to `frontend-net`, allowing it to communicate with both tiers.

```bash
docker network connect frontend-net app
```

The web container was placed only in `frontend-net`.

```bash
docker run -d --name web --network frontend-net nginx
```

The resulting network arrangement was:

* `web` connected to `frontend-net`
* `app` connected to `frontend-net` and `backend-net`
* `db` connected to `backend-net`

![Three-Tier Network Setup](Evidence/4.1-Three-Tier-Network-Setup.png)

**Figure 4.1: Three-Tier Network and Container Setup.** The web and database containers were placed on separate networks, while the application container was connected to both networks.

The connectivity from the web container to the database port was tested.

```bash
docker exec web bash -c \
  'timeout 3 bash -c "</dev/tcp/db/6379" 2>/dev/null && echo REACHABLE || echo BLOCKED'
```

The result was:

```text
BLOCKED
```

Connectivity from the application container to the database was then tested.

```bash
docker exec app bash -c \
  'timeout 3 bash -c "</dev/tcp/db/6379" 2>/dev/null && echo REACHABLE || echo BLOCKED'
```

The result was:

```text
REACHABLE
```

The web container could not reach the database directly because they did not share a Docker network. However, the application container could reach the database through `backend-net`.

![Network Segmentation Test](Evidence/4.2-Network-Segmentation-Test.png)

**Figure 4.2: Network Segmentation Connectivity Test.** Direct communication from the web tier to the database was blocked, while the application tier successfully reached the database.

---

### Task 5: Default-Deny Firewall Rules

A temporary Alpine container with the `NET_ADMIN` capability was used to demonstrate a default-deny firewall.

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
  apk add -q iptables; \
  iptables -P INPUT DROP; \
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
  iptables -A INPUT -i lo -j ACCEPT; \
  iptables -L INPUT -n'
```

The firewall used `DROP` as the default policy for incoming traffic. It then included explicit rules to allow HTTPS traffic on TCP port `443` and internal loopback communication.

The output showed:

```text
Chain INPUT (policy DROP)
ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:443
ACCEPT all -- 0.0.0.0/0 0.0.0.0/0
```

This demonstrated the default-deny principle because traffic was rejected unless an explicit rule allowed it.

![Default-Deny Firewall](Evidence/5-Default-Deny-Firewall-Rules.png)

**Figure 5: Default-Deny Firewall Configuration.** The firewall rejected incoming traffic by default while explicitly allowing TCP port `443` and loopback communication.

---

### Task 6: Container Hardening and Vulnerability Scanning

A hardened Nginx container was started using several security controls.

```bash
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged
```

The container included the following hardening measures:

* `--user 1000:1000` ran the service as a non-root user.
* `--read-only` prevented modification of the root filesystem.
* `--cap-drop=ALL` removed unnecessary Linux capabilities.
* `--security-opt no-new-privileges` prevented the process from gaining additional privileges.
* `--tmpfs /tmp` provided a temporary writable location without making the root filesystem writable.

The container status was checked.

```bash
docker ps --filter name=hardened
```

The container remained operational with a status of `Up`.

The non-root user and read-only filesystem were verified.

```bash
docker inspect hardened --format 'User={{.Config.User}}
ReadOnly={{.HostConfig.ReadonlyRootfs}}'
```

The output was:

```text
User=1000:1000
ReadOnly=true
```

![Hardened Container Verification](Evidence/6.1-Hardened-Container-Verification.png)

**Figure 6.1: Hardened Container Configuration.** The Nginx container remained operational while running as user `1000:1000` with a read-only root filesystem.

The `nginx:alpine` image was scanned for high and critical vulnerabilities using Trivy.

```bash
docker run --rm aquasec/trivy image \
  --severity HIGH,CRITICAL \
  nginx:alpine | head -20
```

During the first scan, Trivy downloaded and updated its vulnerability database.

![Trivy Database Download](Evidence/6.2-Trivy-Database-Download.png)

**Figure 6.2: Trivy Vulnerability Database Download.** Trivy downloaded the latest vulnerability database before scanning the container image.

The scan produced the following summary:

```text
Total: 2 (HIGH: 2, CRITICAL: 0)
```

This indicated that two high-severity vulnerabilities and no critical vulnerabilities were detected in the scanned `nginx:alpine` image.

![Trivy Vulnerability Scan](Evidence/6.3-Trivy-Vulnerability-Scan-Result.png)

**Figure 6.3: Trivy Vulnerability Scan Result.** The scan detected two high-severity vulnerabilities and no critical vulnerabilities in the `nginx:alpine` image.

#### Hardening Measures and Reduced Attack Surfaces

| Hardening measure     | Attack or risk reduced                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| Non-root user         | Reduces the impact of a container compromise because the service does not have root privileges.             |
| Read-only filesystem  | Prevents attackers from modifying system files or installing malicious files in the container filesystem.   |
| Drop all capabilities | Removes unnecessary Linux privileges that could be abused for privilege escalation or system-level actions. |
