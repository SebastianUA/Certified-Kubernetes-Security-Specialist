# Certified Kubernetes Security Specialist (CKS) in 2023-2024


A Certified Kubernetes Security Specialist (CKS) is an accomplished Kubernetes practitioner (must be CKA certified) who has demonstrated competence on a broad range of best practices for securing container-based applications and Kubernetes platforms during build, deployment, and runtime.

<p align="center">
  <img width="360" src="kubernetes-security-specialist.png">
</p>

# Certification

- Duration of Exam: **120 minutes**
- Number of questions: **15-20 hands-on performance-based tasks**
- Passing score: **67%**
- Certification validity: **2 years**
- Prerequisite: valid **CKA certification**
- Cost: **$395 USD**
- Exam Eligibility: **12 Month**, with a free retake within this year.
- Software Version: **Kubernetes v1.27**
- [The official website with certification](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist)
- [CNCF Exam Curriculum repository](https://github.com/cncf/curriculum/)
- [Tips & Important Instructions: CKS](https://docs.linuxfoundation.org/tc-docs/certification/important-instructions-cks)
- [Candidate Handbook](https://docs.linuxfoundation.org/tc-docs/certification/lf-handbook2)
- [Verify Certification](https://training.linuxfoundation.org/certification/verify/)

# Structure of certification

## Cluster Setup - 10%

### 1. Use Network security policies to restrict cluster level access

Examples:
 - <details><summary>Example_1: Create default deny networking policy with <b>deny-all</b> name in <b>monitoring</b> namespace:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: NetworkPolicy
	metadata:
	name: deny-all
	namespace: monitoring
	spec:
	podSelector: {}
	policyTypes:
	   - Egress
	egress: {}
	```

</details>
 
 - <details><summary>Example_2: Create networking policy with <b>api-allow</b> name and create a restriction access to <b>api-allow</b> application that has deployed on <b>default</b> namespace and allow access only from <b>app2</b> pods:</summary>
	
	```
	---
	kind: NetworkPolicy
	apiVersion: networking.k8s.io/v1
	metadata:
	name: api-allow
	spec:
	podSelector:
	   matchLabels:
	   run: my-app
	ingress:
	- from:
		- podSelector:
			matchLabels:
			   run: app2
	```

</details>

Other examples you can find in [hands-on with Kubernetes network policy](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/tree/main/hands-on/Kubernetes-network-policy).

**Useful official documentation**

- [network-policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

**Useful non-official documentation**

- [networking policy editor](https://editor.networkpolicy.io)

- [kubernetes network policy recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

- [An Introduction to Kubernetes Network Policies for Security People](https://reuvenharrison.medium.com/an-introduction-to-kubernetes-network-policies-for-security-people-ba92dd4c809d)

- [Testing Kubernetes network policies behavior](https://github.com/Tufin/test-network-policies/tree/master)

### 2. Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

Examples:
 - <details><summary>Example_1: Fix issues that provided in CIS file (some example of the file):</summary>
	
	```
	[INFO] 1 Master Node Security Configuration
	[INFO] 1.2 API Server
	[FAIL] 1.2.20 Ensure that the --profiling argument is set to false (Automated)

	== Remediations master ==
	1.2.20 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
	on the master node and set the below parameter.
	--profiling=false


	== Summary master ==
	0 checks PASS
	1 checks FAIL
	0 checks WARN
	0 checks INFO

	== Summary total ==
	0 checks PASS
	1 checks FAIL
	0 checks WARN
	0 checks INFO
	```
</details>

 - <details><summary>Example_2: Fix issues of 1.3.2 part with <b>kube-bench</b>:</summary>
	
	```
	$ kube-bench run --targets master --check 1.3.2 

	[INFO] 1 Master Node Security Configuration
	[INFO] 1.3 Controller Manager
	[FAIL] 1.3.2 Ensure that the --profiling argument is set to false (Automated)

	== Remediations master ==
	1.3.2 Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml
	on the master node and set the below parameter.
	--profiling=false


	== Summary master ==
	0 checks PASS
	1 checks FAIL
	0 checks WARN
	0 checks INFO

	== Summary total ==
	0 checks PASS
	1 checks FAIL
	0 checks WARN
	0 checks INFO
	```

	Then, going to fix:
	```
	...
	containers:
	- command:
		- kube-apiserver
		- --profiling=false
	...
		image: registry.k8s.io/kube-apiserver:v1.22.2
	...
	```

</details>

**Useful non-official documentation**

- [cisecurity website](https://www.cisecurity.org/benchmark/kubernetes)
- [kube-bench](https://github.com/aquasecurity/kube-bench)

### 3. Properly set up Ingress objects with security control

Examples:
 - <details><summary>Example_1: Create ingress with <b>ingress-app1</b> name in <b>app1</b> namespace for the <b>app1-svc</b> service:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: Ingress
	metadata:
	name: ingress-app1
	namespace: app1
	annotations:
		nginx.ingress.kubernetes.io/rewrite-target: /
	spec:
	ingressClassName: nginx
	rules:
	- http:
		paths:
		- path: /health
			pathType: Prefix
			backend:
			service:
				name: app1-svc
				port:
				number: 80
	```

</details>
 
 - <details><summary>Example_2: Create ingress with <b>ingress-app1</b> name in <b>app1</b> namespace (with TLS):</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: Ingress
	metadata:
	name: ingress-app1
	namespace: app1
	annotations:
		nginx.ingress.kubernetes.io/rewrite-target: /
	spec:
	ingressClassName: nginx
	tls:
	- hosts:
		- "local.domail.name"
		secretName: local-domain-tls
	rules:
	- http:
		paths:
		- path: /health
			pathType: Prefix
			backend:
			service:
				name: app1-svc
				port:
				number: 80
	```

</details>

**NOTE:** You should create the needed <b>local-domain-tls</b> secret for Ingress with certifications:
```
$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt -subj "/CN=local.domail.name/O=local.domail.name"
$ kubectl -n app1 create secret tls local-domain-tls --key cert.key --cert cert.crt
```

**Useful non-official documentation**

- [ingress](https://kubernetes.io/docs/concepts/services-networking/ingress)
- [ingress with tls](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

### 4. Protect node metadata and endpoints
It's part of networking policy where you can restrict access to metadata/endpoints.

Examples:
 - <details><summary>Create metadata restriction with networking policy of <b>deny-all-allow-metadata-access</b> name in <b>monitoring</b> namespace to deny all except <b>1.1.1.1</b> IP:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: NetworkPolicy
	metadata:
  		name: deny-all-allow-metadata-access
		namespace: monitoring
	spec:
  		podSelector: {}
  		policyTypes:
  		- Egress
  		egress:
  		- to:
    	  - ipBlock:
      		cidr: 0.0.0.0/0
            except:
      		- 1.1.1.1/32
	```

</details>

**Useful official documentation**

- [network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

**Useful non-official documentation**

- [restricting-cloud-metadata-api-access](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)

- [kubelet-authn-authz](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)


### 5. Minimize the use of and access to, GUI elements

Nothing specific to add to this topic.

**Useful official documentation**
- [web-ui-dashboard](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)

**Useful non-official documentation**
- [on-securing-the-kubernetes-dashboard](https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca)

### 6. Verify platform binaries before deploying 

Examples:
 - <details><summary>Compare binary file of kubelet on the current host and with kubelet 1.27 that you must download from official release:</summary>
	
	```
	$ sha512sum $(which kubelet) | cut -c-10
	$ wget -O kubelet https://dl.k8s.io/$(/usr/bin/kubelet --version | cut -d " " -f2)/bin/linux/$(uname -m)/kubelet 
	$ sha512sum ./kubelet | cut -c -10
	```

</details>

**Useful non-official documentation**
- [kubernetes-releases](https://github.com/kubernetes/kubernetes/releases)


## Cluster Hardening - 15%

### 1. Restrict access to Kubernetes API

Examples:
 - <details><summary>Example_1: Blocking anonymous access to use API:</summary>
	
	<details><summary>Check if anonymous access is enabled (if so, - it should be disabled):</summary>
	
		cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "anonymous-auth"

	</details>

	<details><summary>Fix if it's enabled:</summary>
	
		TBD!
		
	</details>
	
</details>

 - <details><summary>Example_2: Blocking insecure port:</summary>

	<details><summary>Check if insecure port is using (if so, - it should be changed to 0):</summary>
	
		cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "insecure-port"

	</details>

	<details><summary>Fix if it's open:</summary>
	
		TBD!
		
	</details>
	
</details>

 - <details><summary>Example_3: NodeRestriction enabling:</summary>

	<details><summary>Check if Node restriction is enabled (if so, - it should NodeRestriction):</summary>
	
		cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "enable-admission-plugins"

	</details>

	Open the `/etc/kubernetes/manifests/kube-apiserver.yaml` file with some editor.

	<details><summary>Let's enable NodeRestriction on Controlplane node</summary>

		spec:
			containers:
			- command:
				- kube-apiserver
				- --advertise-address=172.30.1.2
				- --allow-privileged=true
				- --authorization-mode=Node,RBAC
				- --client-ca-file=/etc/kubernetes/pki/ca.crt
				- --enable-admission-plugins=NodeRestriction
				- --enable-bootstrap-token-auth=true
		
	</details>

	Let's check the configurations:
	```
	ssh node01

    export KUBECONFIG=/etc/kubernetes/kubelet.conf
    k label node controlplane killercoda/two=123 # restricted
    k label node node01 node-restriction.kubernetes.io/two=123 # restricted
    k label node node01 test/two=123 # works
	```

</details>

- <details><summary>Example_4: Kuberneter API troubleshooting:</summary>

	<details><summary>First al all, checking:</summary>
	
		$ cat /var/log/syslog | grep kube-apiserver

		or

		$ cat /var/log/syslog | grep -Ei "apiserver" | grep -Ei "line"

	</details>

	<details><summary>Secondly, checking:</summary>
	
		$ journalctl -xe | grep apiserver

	</details>

	<details><summary>Lastly, checking:</summary>
	
		$ crictl ps -a | grep api
		$ $ crictl logs fbb80dac7429e

	</details>

</details>

- <details><summary>Example_5: Certificate signing requests sign manually:</summary>

	First of all, we should have key. Let's get it through openssl:
	```
	$ openssl genrsa -out 60099.key 2048
	```

	Next, runnning the next command to generate certificate:
	```
	$ openssl req -new -key 60099.key -out 60099.csr
	```

	Note: set Common Name = 60099@internal.users

	<details><summary>Certificate signing requests sign manually (manually sign the CSR with the K8s CA file to generate the CRT):</summary>
	
		$ openssl x509 -req -in 60099.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out 60099.crt -days 500

	</details>

	<details><summary>Set credentials & context:</summary>
	
		$ k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt
		$ k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
		$ k config get-contexts
		$ k config use-context 60099@internal.users

	</details>

	<details><summary>Checks:</summary>
	
		$ k get ns

		$ k get po

	</details>

</details>

- <details><summary>Example_6: Certificate signing requests sign K8S:</summary>

	First of all, we should have key. Let's get it through openssl:
	```
	$ openssl genrsa -out 60099.key 2048
	```

	Next, runnning the next command to generate certificate:
	```
	$ openssl req -new -key 60099.key -out 60099.csr
	```

	Note: set Common Name = 60099@internal.users

	<details><summary>Convert the CSR file into base64:</summary>
	
		$ cat 60099.csr | base64 -w 0

	</details>

	<details><summary>Copy it into the YAML:</summary>
	
		apiVersion: certificates.k8s.io/v1
		kind: CertificateSigningRequest
		metadata:
		name: 60099@internal.users # ADD
		spec:
		groups:
			- system:authenticated
		request: CERTIFICATE_BASE64_HERE
		signerName: kubernetes.io/kube-apiserver-client
		usages:
			- client auth

	</details>

	<details><summary>Create and approve:</summary>
	
		$ k -f csr.yaml create

		$ k get csr # pending

		$ k certificate approve 60099@internal.users

		$ k get csr # approved

		$ k get csr 60099@internal.users -ojsonpath="{.status.certificate}" | base64 -d > 60099.crt

	</details>

	<details><summary>Set credentials & context:</summary>
	
		$ k config set-credentials 60099@internal.users --client-key=60099.key --client-certificate=60099.crt
		$ k config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
		$ k config get-contexts
		$ k config use-context 60099@internal.users

	</details>

	<details><summary>Checks:</summary>
	
		$ k get ns

		$ k get po

	</details>

</details>

**Useful official documentation**

- [controlling-access](https://kubernetes.io/docs/concepts/security/controlling-access/)
- [controlling-access#api-server-ports-and-ips](https://kubernetes.io/docs/concepts/security/controlling-access/#api-server-ports-and-ips)
- [Block anonymous requests](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
- [certificates](https://kubernetes.io/docs/tasks/administer-cluster/certificates/)
- [certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)

**Useful non-official documentation**

- None


### 2. Use Role Based Access Controls to minimize exposure

Examples:
 - <details><summary>Example_1: Working with RBAC (roles and role bindings):</summary>

	<details><summary>Create role & rolebinding:</summary>
	
		k create role role_name --verb=get,list,watch --resource=pods
		k create rolebinding role_name_binding --role=role_name --user=captain --group=group1

	</details>

	<details><summary>Verify:</summary>
	
		k auth can-i get pods --as captain -n kube-public
		k auth can-i list pods --as captain -n default

	</details>
	
</details>

 - <details><summary>Example_2: Working with RBAC (cluster roles and cluster role bindings):</summary>

	<details><summary>Create clusterrole & clusterrolebinding:</summary>
	
		k create clusterrole cluster_role --verb=get,list,watch --resource=pods
		k create clusterrolebinding cluster_role_binding --clusterrole=cluster_role --user=cap

	</details>

	<details><summary>Verify:</summary>
	
		k auth can-i list pods --as cap -n kube-public
		k auth can-i list pods --as cap -n default

	</details>

</details>

 - <details><summary>Example_3: Working with Service Account and RBAC:</summary>

	<details><summary> Create Service Account and RBAC:</summary>
	
		k -n name_space_1 create sa ser_acc
		k create clusterrolebinding ser_acc-view --clusterrole view --serviceaccount name_space_1:ser_acc

	</details>

	<details><summary> Verify:</summary>
	
		k auth can-i update deployments --as system:serviceaccount:name_space_1:ser_acc -n default
		k auth can-i update deployments --as system:serviceaccount:name_space_1:ser_acc -n name_space_1

	</details>	

</details>

You must know to how:
- To create roles & role bindings.
- To create cluster roles & cluster role bindings.
- To create service account and grant it with some permission.
- To find needed resources and change/add permissions.

**Useful official documentation**

- [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

**Useful non-official documentation**

- [advocacy site for Kubernetes RBAC](https://rbac.dev/)
- [simplify-kubernetes-resource-access-rbac-impersonation](https://docs.bitnami.com/tutorials/simplify-kubernetes-resource-access-rbac-impersonation/)
- [Manage Role Based Access Control (RBAC)](https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/01-Cluster%20Architcture,%20Installation%20and%20Configuration.md#manage-role-based-access-control-rbac)

### 3. Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

Examples:
 - <details><summary>Example_1: Opt out of automounting API credentials for a service account (Opt out at service account scope):</summary>
	
	```
	---
	apiVersion: v1
	kind: ServiceAccount
	metadata:
	name: build-robot
	automountServiceAccountToken: false
	```
</details>

 - <details><summary>Example_2: Opt out of automounting API credentials for a service account (Opt out at pod scope):</summary>
	
	```
	---
	apiVersion: v1
	kind: Pod
	metadata:
	name: cks-pod
	spec:
	serviceAccountName: default
	automountServiceAccountToken: false
	```
</details>

**Useful official documentation**

- [Authorization Modes](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules)
- [Use the default service account to access the API server](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)
- [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Default roles and role bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)

**Useful non-official documentation**

- [advocacy site for Kubernetes RBAC](https://rbac.dev/)

You must know to how:
- To create service account and greant it with some permission.
- To find needed resources and change/add permissions.


### 4. Update Kubernetes frequently

Examples:
 - <details><summary>Example_1: K8S upgrades(Controlplane):</summary>
	
	```
	k drain master --ignore-deamonsets
	apt update -y
	apt-cache show kubeadm | grep 1.22
	apt install kubeadm=1.22.5-00 kubelet=1.22.5-00 kubectl=1.22.5-00

	kubeadm upgrade plan
	kubeadm upgrade apply v1.22.5

	k uncordon master
	```
</details>

 - <details><summary>Example_2: K8S upgrades(Nodes):</summary>
	
	```
	k drain node --ignore-deamonsets
	apt update -y
	apt-cache show kubeadm | grep 1.22
	apt install kubeadm=1.22.5-00 kubelet=1.22.5-00 kubectl=1.22.5-00

	kubeadm upgrade node

	service kubelet restart
	```
</details>

**Useful official documentation**

- [kubeadm upgrade](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)
- [kubeadm upgrade](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)


You must know to how:
- Upgrade the K8S clusters




## System Hardening - 15%

### 1. Minimize host OS footprint (reduce attack surface)

Examples:
 - <details><summary>Example_1: Use Seccomp (use strace commands):</summary>
	
	```
	$ strace -c ls /root
	```
</details>

 - <details><summary>Example_2: Use AppArmor:</summary>
	
	<details><summary> Get AppArmor profiles:</summary>
		
		$ apparmor_status
   
		$ aa-status

	</details>

	<details><summary> Load AppArmor profile:</summary>
		
		$ apparmor_parser -q apparmor_config

	</details>

</details>

 - <details><summary>Example_3: PSA enforces:</summary>
	
	```
	Pod Security admissions (PSA) support has been added for clusters with Kubernetes v1.23 and above. PSA defines security restrictions for a broad set of workloads and replace Pod Security Policies in Kubernetes v1.25 and above. The Pod Security Admission controller is enabled by default in Kubernetes clusters v1.23 and above. To configure its default behavior, you must provide an admission configuration file to the kube-apiserver when provisioning the cluster.
	```
</details>

 - <details><summary>Example_4: Apply host updates:</summary>
	
	```
	$ sudo apt update && sudo apt install unattended-upgrades -y
	$ systemctl status unattended-upgrades.service
	```
</details>

 - <details><summary>Example_5: Install minimal required OS fingerprint:</summary>
	
	```
	It is best practice to install only the packages you will use because each piece of software on your computer could possibly contain a vulnerability. Take the opportunity to select exactly what packages you want to install during the installation. If you find you need another package, you can always add it to the system later.
	```
</details>

 - <details><summary>Example_6: Identify and address open ports:</summary>

	<details><summary>Using lsof command and check if 8080 is open or not:</summary>

		$ lsof -i :8080

	</details>
	<details><summary>Using netstat command - check if 66 is oppen and kill the process and delete the binary:</summary>

		$ apt install net-tools
		$ netstat -natpl | grep 66
		$ ls -l /proc/22797/exe
		$ rm -f /usr/bin/app1
		$ kill -9 22797

	</details>

</details>

 - <details><summary>Example_7: Remove unnecessary packages. For example, find and delete httpd package on the host:</summary>
	
	```
	$ apt show httpd
	$ apt remove httpd -y
	```
</details>

 - <details><summary>Example_8: Find service that runs on the host and stop it. For example, find and stop httpd service on the host:</summary>
	
	```
	$ service httpd status
	$ service httpd stop
	$ service httpd status
	```
</details>

 - <details><summary>Example_9: Working with users (Create, delete, add user to needed groups. Grant some permission):</summary>
	
	```
	TBD!
	```
</details>

 - <details><summary>Example_10: Working with kernel modules on the host (get, load, unload, etc):</summary>
	
	```
	TBD!
	```
</details>

**Useful official documentation**

- [securing-a-cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)

**Useful non-official documentation**

- [how-to-keep-ubuntu-20-04-servers-updated](https://www.digitalocean.com/community/tutorials/how-to-keep-ubuntu-20-04-servers-updated)
- [enforce-standards-namespace-labels](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)
- [psa-label-enforcer-policy](https://github.com/kubewarden/psa-label-enforcer-policy)
- [migrating-from-pod-security-policies-a-comprehensive-guide-part-1-transitioning-to-psa](https://hackernoon.com/migrating-from-pod-security-policies-a-comprehensive-guide-part-1-transitioning-to-psa)
- [using-kyverno-with-pod-security-admission](https://kyverno.io/blog/2023/06/12/using-kyverno-with-pod-security-admission/)
- [add-psa-labels](https://kyverno.io/policies/psa/add-psa-labels/add-psa-labels/)
- [pod-security-admission](https://rke.docs.rancher.com/config-options/services/pod-security-admission)
- [pod-security-standards](https://www.eksworkshop.com/docs/security/pod-security-standards/)
- [Implementing Pod Security Standards in Amazon EKS](https://aws.amazon.com/blogs/containers/implementing-pod-security-standards-in-amazon-eks/)

### 2. Minimize IAM roles

TBD!

**Useful official documentation**

- [access-authn-authz](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)

### 3. Minimize external access to the network

TBD!

**Useful official documentation**

- [network-policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### 4. Appropriately use kernel hardening tools such as AppArmor, and SecComp

Examples:
 - <details><summary>Example_1: Working with Privilege Escalation:</summary>
	
	<details><summary> An example of configuration:</summary>
		
		---
		apiVersion: apps/v1
		kind: Deployment
		metadata:
		name: pod-with-apparmor
		namespace: apparmor
		spec:
		replicas: 3
		selector:
			matchLabels:
			app: pod-with-apparmor
		strategy: {}
		template:
			metadata:
			labels:
				app: pod-with-apparmor
			annotations:
				container.apparmor.security.beta.kubernetes.io/httpd: localhost/docker-default
			spec:
			containers:
			- image: httpd:latest
				name: httpd

	</details>

	<details><summary> Apply the prepared configuration file:</summary>
		
		k apply -f pod-with-apparmor.yaml

	</details>

	<details><summary> Checks:</summary>
		$ crictl ps -a | grep httpd

		$ crictl inspect e428e2a3e9324 | grep apparmor
          "apparmor_profile": "localhost/docker-default"
        "apparmorProfile": "docker-default",

	</details>

**Useful official documentation**

- [pod-security-admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [apparmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

**Useful non-official documentation**

- [apparmor](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [Container Security](https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf?utm_medium=email&_hsmi=85733108&_hsenc=p2ANqtz--tQO3LhW0VqGNthE1dZqnfki1pYhEq-I_LU87M03pmQlvhXhA1lO4jO3vLjN4NtcbEiFyIL2lEBlzzMHe96VPXERZryw&utm_content=85733108&utm_source=hs_automation)

### 5. Principle of least privilege

Examples:
 - <details><summary>Example_1: Working with Privilege Escalation:</summary>
	
	<details><summary> An example of configuration:</summary>
		
		---
		apiVersion: v1
		kind: Pod
		metadata:
		labels:
			run: my-ro-pod
		name: application
		namespace: sun
		spec:
		containers:
		- command:
			- sh
			- -c
			- sleep 1d
			image: busybox:1.32.0
			name: my-ro-pod
			securityContext:
				allowPrivilegeEscalation: false
		dnsPolicy: ClusterFirst
		restartPolicy: Always

	</details>

	<details><summary> Checks:</summary>
		
		TBD!

	</details>
	
</details>

 - <details><summary>Example_2: Working with Privileged containers:</summary>
	
	<details><summary> Run a Pod through CLI:</summary>
		
		k run privileged-pod --image=nginx:alpine --privileged

	</details>

	<details><summary> An example of configuration:</summary>
		
		---
		apiVersion: v1
		kind: Pod
		metadata:
		labels:
			run: privileged-pod
		name: privileged-pod
		spec:
		containers:
		- command:
			- sh
			- -c
			- sleep 1d
			image: nginx:alpine
			name: privileged-pod
			securityContext:
				privileged: true
		dnsPolicy: ClusterFirst
		restartPolicy: Always

	</details>

	<details><summary> Checks:</summary>
		
		TBD!

	</details>
	
</details>


**Useful official documentation**

- None




## Minimize Microservice Vulnerabilities - 20%

### 1. Setup appropriate OS-level security domains

TBD!

**Useful official documentation**

- None

**Useful non-official documentation**

- [opa-gatekeeper-policy-and-governance-for-kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
- [openpolicyagent](https://www.openpolicyagent.org/docs/latest/kubernetes-primer/)
- [openpolicyagent online editor](https://play.openpolicyagent.org/)
- [gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/)
- [security context for pods](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [kubernetes-security-psp-network-policy](https://sysdig.com/blog/kubernetes-security-psp-network-policy/)


### 2. Manage Kubernetes secrets

TBD! 

**Useful official documentation**

- [distribute-credentials-secure](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)
- [secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [encrypt-data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [kube-apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [etcd encryption](https://etcd.io/docs/v3.5/op-guide/configuration/#security)

**Useful non-official documentation**

- None

### 3. Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)

Examples:
 - <details><summary>Example_1: Use ReadOnly Root FileSystem. Create a new Pod named my-ro-pod in Namespace application of image busybox:1.32.0. Make sure the container keeps running, like using sleep 1d. The container root filesystem should be read-only:</summary>
	
	<details><summary> Create RuntimeClass class, something like:</summary>
		
		apiVersion: node.k8s.io/v1
		kind: RuntimeClass
		metadata:
		name: gvisor
		handler: runsc

	</details>

	<details><summary> Deploy a new pod with created RuntimeClass, an example:</summary>
		
		---
		apiVersion: v1
		kind: Pod
		metadata:
		name: sec
		spec:
		runtimeClassName: gvisor
		containers:
			- image: nginx:1.21.5-alpine
			name: sec
		dnsPolicy: ClusterFirst
		restartPolicy: Always

	</details>

	
</details>

**Useful official documentation**

- [runtime-class](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [encrypt-data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

**Useful non-official documentation**

- [gvisor](https://gvisor.dev/docs/user_guide/install/)
- [runtime-class-examples](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/585-runtime-class/README.md#examples)


### 4. Implement pod-to-pod encryption by use of mTLS

TBD!

**Useful official documentation**

- [mTLS](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)

**Useful non-official documentation**

- [mTLS](https://www.istioworkshop.io/11-security/01-mtls/)
- [Istio](https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/)
- [Linkerd](https://linkerd.io/2/features/automatic-mtls/)


## Supply Chain Security - 20% 

### 1. Minimize base image footprint

Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
Do not include uncessary software not required for container during runtime e.g build tools and utilities, troubleshooting and debug binaries.

Examples:
- <details><summary>Example_1: Create a Pod named nginx-sha-pod which uses the image digest nginx@sha256:ca045ecbcd423cec50367a194d61fd846a6f0964f4999e8d692e5fcf7ebc903f:</summary>

	```
	k run nginx-sha-pod --image=nginx@sha256:ca045ecbcd423cec50367a194d61fd846a6f0964f4999e8d692e5fcf7ebc903f
	```

</details>

- <details><summary>Example_2: Convert the existing Deployment nginx-sha-deployment to use the image digest of the current tag instead of the tag:</summary>

	
	Getting labels of deployment:
	```
	k get deploy nginx-sha-deployment --show-labels
	```
	
	Get pod with labels:
	```
	k get pod -l app=nginx-sha-deployment -oyaml | grep imageID
	```

	Edit deploy and put needed sha
	```
	k edit deploy nginx-sha-deployment
	```

	Checks:
	```
	k get pod -l app=nginx-sha-deployment -oyaml | grep image:
	```

</details>

- <details><summary>Example_3: Container Image Footprint:</summary>

	In the current folder you have Dockerfile, let's build it with `golden-image` name:
	```
	docker build -t golden-image .
	```

	Run a container with `cointainer-1` name:
	```
	docker run --name cointainer-1 -d golden-image
	```

</details>

- <details><summary>Example_4: Harden a given Docker Container:</summary>

	In the current folder you have Dockerfile, let's build it with `golden-image` name:
	```
	TBD
	```

</details>


**Useful official documentation**

- None

**Useful non-official documentation**

- [7-best-practices-for-building-containers](https://cloud.google.com/blog/products/containers-kubernetes/7-best-practices-for-building-containers)
- [smaller-docker-images](https://learnk8s.io/blog/smaller-docker-images)
-[kubernetes-best-practices-how-and-why-to-build-small-container-images](https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-how-and-why-to-build-small-container-images)
-[best-practices-for-building-containers](https://cloud.google.com/architecture/best-practices-for-building-containers#build-the-smallest-image-possible)
-[multi-stages](https://docs.docker.com/build/building/multi-stage/)
-[tips-to-reduce-docker-image-sizes](https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34)

### 2. Secure your supply chain: whitelist allowed registries, sign and validate images

Examples:
 - <details><summary>Example_1: Use ImagePolicyWebhook:</summary>

	<details><summary>First of all, let create admission config /etc/kubernetes/policywebhook/admission_config.json</summary>
	
		{
			"apiVersion": "apiserver.config.k8s.io/v1",
			"kind": "AdmissionConfiguration",
			"plugins": [
				{
					"name": "ImagePolicyWebhook",
					"configuration": {
						"imagePolicy": {
						"kubeConfigFile": "/etc/kubernetes/policywebhook/kubeconf",
						"allowTTL": 100,
						"denyTTL": 50,
						"retryBackoff": 500,
						"defaultAllow": false
						}
					}
				}
			]
		}
	
	</details>

	<details><summary>Then, create /etc/kubernetes/policywebhook/kubeconf with the settings. For example:</summary>
		apiVersion: v1
		kind: Config

		# clusters refers to the remote service.
		clusters:
		- cluster:
			certificate-authority: /etc/kubernetes/policywebhook/external-cert.pem  # CA for verifying the remote service.
			server: https://localhost:1234                   # URL of remote service to query. Must use 'https'.
		name: image-checker

		contexts:
		- context:
			cluster: image-checker
			user: api-server
		name: image-checker
		current-context: image-checker
		preferences: {}

		# users refers to the API server's webhook configuration.
		users:
		- name: api-server
		user:
			client-certificate: /etc/kubernetes/policywebhook/apiserver-client-cert.pem     # cert for the webhook admission controller to use
			client-key:  /etc/kubernetes/policywebhook/apiserver-client-key.pem             # key matching the cert
	
	</details>

	<details><summary>The /etc/kubernetes/manifests/kube-apiserver.yaml configuration of kube-apiserver, for example:</summary>

		apiVersion: v1
		kind: Pod
		metadata:
		annotations:
			kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 172.30.1.2:6443
		creationTimestamp: null
		labels:
			component: kube-apiserver
			tier: control-plane
		name: kube-apiserver
		namespace: kube-system
		spec:
		containers:
		- command:
			- kube-apiserver
			- --advertise-address=172.30.1.2
			- --allow-privileged=true
			- --authorization-mode=Node,RBAC
			- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
			- --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.json
			- --client-ca-file=/etc/kubernetes/pki/ca.crt
			- --enable-admission-plugins=NodeRestriction
			- --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.json
			- --enable-bootstrap-token-auth=true
			- --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
			- --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
			- --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
			- --etcd-servers=https://127.0.0.1:2379
			- --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
			- --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
			- --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
			- --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
			- --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
			- --requestheader-allowed-names=front-proxy-client
			- --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
			- --requestheader-extra-headers-prefix=X-Remote-Extra-
			- --requestheader-group-headers=X-Remote-Group
			- --requestheader-username-headers=X-Remote-User
			- --secure-port=6443
			- --service-account-issuer=https://kubernetes.default.svc.cluster.local
			- --service-account-key-file=/etc/kubernetes/pki/sa.pub
			- --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
			- --service-cluster-ip-range=10.96.0.0/12
			- --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
			- --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
			image: registry.k8s.io/kube-apiserver:v1.27.1
			imagePullPolicy: IfNotPresent
			livenessProbe:
			failureThreshold: 8
			httpGet:
				host: 172.30.1.2
				path: /livez
				port: 6443
				scheme: HTTPS
			initialDelaySeconds: 10
			periodSeconds: 10
			timeoutSeconds: 15
			name: kube-apiserver
			readinessProbe:
			failureThreshold: 3
			httpGet:
				host: 172.30.1.2
				path: /readyz
				port: 6443
				scheme: HTTPS
			periodSeconds: 1
			timeoutSeconds: 15
			resources:
			requests:
				cpu: 50m
			startupProbe:
			failureThreshold: 24
			httpGet:
				host: 172.30.1.2
				path: /livez
				port: 6443
				scheme: HTTPS
			initialDelaySeconds: 10
			periodSeconds: 10
			timeoutSeconds: 15
			volumeMounts:
			- mountPath: /etc/kubernetes/policywebhook
			name: policywebhook
			readyOnly: true
			- mountPath: /etc/ssl/certs
			name: ca-certs
			readOnly: true
			- mountPath: /etc/ca-certificates
			name: etc-ca-certificates
			readOnly: true
			- mountPath: /etc/pki
			name: etc-pki
			readOnly: true
			- mountPath: /etc/kubernetes/pki
			name: k8s-certs
			readOnly: true
			- mountPath: /usr/local/share/ca-certificates
			name: usr-local-share-ca-certificates
			readOnly: true
			- mountPath: /usr/share/ca-certificates
			name: usr-share-ca-certificates
			readOnly: true
		hostNetwork: true
		priority: 2000001000
		priorityClassName: system-node-critical
		securityContext:
			seccompProfile:
			type: RuntimeDefault
		volumes:
		- hostPath:
			path: /etc/kubernetes/policywebhook
			type: DirectoryOrCreate
			name: policywebhook
		- hostPath:
			path: /etc/ssl/certs
			type: DirectoryOrCreate
			name: ca-certs
		- hostPath:
			path: /etc/ca-certificates
			type: DirectoryOrCreate
			name: etc-ca-certificates
		- hostPath:
			path: /etc/pki
			type: DirectoryOrCreate
			name: etc-pki
		- hostPath:
			path: /etc/kubernetes/pki
			type: DirectoryOrCreate
			name: k8s-certs
		- hostPath:
			path: /usr/local/share/ca-certificates
			type: DirectoryOrCreate
			name: usr-local-share-ca-certificates
		- hostPath:
			path: /usr/share/ca-certificates
			type: DirectoryOrCreate
			name: usr-share-ca-certificates
		status: {}

	</details>

	<details><summary>Checks:</summary>
	
		$ crictl ps -a | grep api
		$ crictl logs 91c61357ef147

		$ k run pod --image=nginx
			Error from server (Forbidden): pods "pod" is forbidden: Post "https://localhost:1234/?timeout=30s": dial tcp 127.0.0.1:1234: connect: connection refused
	
	</details>

</details>

**Useful official documentation**

- [admission-controllers#imagepolicywebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
- [extensible-admission-controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

**Useful non-official documentation**

- [why-do-i-need-admission-controllers](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers)


### 3. Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)

Examples:
- <details><summary>Example_1: Static Manual Analysis Docker:</summary>

	```
	TBD!
	```
	
</details>

- <details><summary>Example_2: Static Manual analysis k8s:</summary>

	```
	TBD!
	```
	
</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [statically analyse](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml)
- [kubehunter](https://github.com/aquasecurity/kube-hunter)
- [kubesec](https://kubesec.io/)
- [trivy](https://github.com/aquasecurity/trivy)
- [checkov](https://bridgecrew.io/blog/kubernetes-static-code-analysis-with-checkov/)
- [clair](https://github.com/quay/clair)
- [kube-score](https://kube-score.com/)
- [conftest](https://www.conftest.dev/)
	
### 4. Scan images for known vulnerabilities 

Using trivy to scan images in applications and infra namespaces and define if the images has CVE-2021-28831 and/or CVE-2016-9841 vulnerabilities. Scale down those Deployments to zero if you will find something.

Getting images:
```
$ k -n applications get pod -oyaml | grep image: | sort -rn | uniq
- image: nginx:1.20.2-alpine
- image: nginx:1.19.1-alpine-perl
image: docker.io/library/nginx:1.20.2-alpine
image: docker.io/library/nginx:1.19.1-alpine-perl
```

Let's scan first deployment:
```
$ trivy image nginx:1.19.1-alpine-perl | grep CVE-2021-28831
$ trivy image nginx:1.19.1-alpine-perl | grep CVE-2016-9841
```

Let's scan second deployment:
```
trivy image nginx:1.20.2-alpine | grep CVE-2021-28831
trivy image nginx:1.20.2-alpine | grep CVE-2016-9841
```

Hit on the first one, so we scale down:
```
$ k -n applications scale deploy web1 --replicas 0
```


**Useful official documentation**

- None

**Useful non-official documentation**

- [scan images and run ids](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids)
- [anchore](https://github.com/anchore/anchore-cli#command-line-examples)
- [trivy](https://github.com/aquasecurity/trivy)


## Monitoring, Logging, and Runtime Security - 20%

### 1. Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities

Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities.

Examples:
 - <details><summary>Example_1: Use seccomp:</summary>
	
	```
	TBD
	```
</details>

**Useful official documentation**

- [seccomp]( https://kubernetes.io/docs/tutorials/security/seccomp/)
- [falco](https://falco.org/docs/)

**Useful non-official documentation**

- [how-to-detect-kubernetes-vulnerability-with-falco](https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/)
- [falco-101](https://learn.sysdig.com/falco-101)
- [helm-chart-falco](https://github.com/falcosecurity/charts/tree/master/falco)
- [detect-cve-2020-8557](https://falco.org/blog/detect-cve-2020-8557/)

### 2. Detect threats within a physical infrastructure, apps, networks, data, users, and workloads

TBD!

**Useful official documentation**

- None

**Useful non-official documentation**

- [common-kubernetes-config-security-threats](https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/)
- [guidance-on-kubernetes-threat-modeling](https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/guidance-on-kubernetes-threat-modeling)
- [attack-matrix-kubernetes](https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/)

### 3. Detect all phases of attack regardless of where it occurs and how it spreads

All falco events you should store in `/var/log/falco.txt`. 

Open `/etc/falco/falco.yaml` file and put something like:
```
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco.txt
```

Now, lets configure custom output commands for "Terminal shell in container" rule. So, open `/etc/falco/falco_rules.local.yaml` file and put the next:
```
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    Falco SHELL!!! (user_id=%user.uid repo=%container.image.repository %user.uiduser=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
``` 

Restart Falco service:
```
service falco restart && service falco status
```

Checks:
```
$ k exec -it pod -- sh

$ cat /var/log/syslog | grep falco | grep shell
```

**Useful official documentation**

- [Falco](https://falco.org/)

**Useful non-official documentation**

- [attack-matrix-kubernetes](https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/)
- [mitre-attck-framework-for-container-runtime-security-with-sysdig-falco](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
- [mitigating-kubernetes-attacks](https://www.cncf.io/online-programs/mitigating-kubernetes-attacks/)
- [anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us](https://www.optiv.com/insights/source-zero/blog/anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us)
- [Webinar: Mitigating Kubernetes attacks](https://www.youtube.com/watch?v=HWv8ZKLCawM&ab_channel=CNCF%5BCloudNativeComputingFoundation%5D)

### 4. Perform deep analytical investigation and identification of bad actors within the environment

TBD!

**Useful official documentation**

- [sysdig](https://docs.sysdig.com/en/)

**Useful non-official documentation**

- [monitoring-kubernetes-with-sysdig](https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/)
- [CNCF Webinar: Getting started with container runtime security using Falco](https://www.youtube.com/watch?v=VEFaGjfjfyc&ab_channel=Sysdig)
- [kubernetes-security](https://www.redhat.com/en/topics/containers/kubernetes-security)

### 5. Ensure immutability of containers at runtime

TBD!

**Useful official documentation**

- [Falco](https://falco.org/docs/)
- [Sysdig](https://docs.sysdig.com/)

**Useful non-official documentation**

- [principles-of-container-app-design](https://kubernetes.io/blog/2018/03/principles-of-container-app-design/)
- [why-i-think-we-should-all-use-immutable-docker-images](https://medium.com/sroze/why-i-think-we-should-all-use-immutable-docker-images-9f4fdcb5212f)
- [immutable-infrastructure-your-systems-can-rise-dead](https://techbeacon.com/enterprise-it/immutable-infrastructure-your-systems-can-rise-dead)

### 6. Use Audit Logs to monitor access

Examples:
 - <details><summary>Example_1: Configure the Apiserver for Audit Logging. The log path should be /etc/kubernetes/audit-logs/audit.log on the host and inside the container. The existing Audit Policy to use is at /etc/kubernetes/auditing/policy.yaml . The path should be the same on the host and inside the container. Also, set argument --audit-log-maxsize=3 and set argument --audit-log-maxbackup=4:</summary>
	
	<details><summary> Edit kube-api configuration:</summary>
		
		# vim /etc/kubernetes/manifests/kube-apiserver.yaml

	</details>

	<details><summary> Add the next line to enable auditing:</summary>
		
		---
		spec:
			containers:
			- command:
				- kube-apiserver
				- --audit-policy-file=/etc/kubernetes/auditing/policy.yaml
				- --audit-log-path=/etc/kubernetes/audit-logs/audit.log
				- --audit-log-maxsize=3
				- --audit-log-maxbackup=4

	</details>

	<details><summary> Add the new Volumes:</summary>
		
		volumes:
		- name: audit-policy
			hostPath:
			path: /etc/kubernetes/auditing/policy.yaml
			type: File
		- name: audit-logs
			hostPath:
			path: /etc/kubernetes/audit-logs
			type: DirectoryOrCreate

	</details>

	<details><summary> Add the new VolumeMounts:</summary>
		
		volumeMounts:
		- mountPath: /etc/kubernetes/auditing/policy.yaml
			name: audit-policy
			readOnly: true
		- mountPath: /etc/kubernetes/audit-logs
			name: audit-logs
			readOnly: false

	</details>

	<details><summary> Checks:</summary>
		
		crictl ps -a | grep api

	</details>
	
</details>

**Useful official documentation**

- [audit](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

**Useful non-official documentation**

- [kubernetes-audit-logging](https://docs.sysdig.com/en/docs/sysdig-secure/secure-events/kubernetes-audit-logging/)
- [monitor-kubernetes-audit-logs](https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/)

### 7. ReadOnly Root FileSystem

Examples:
 - <details><summary>Example_1: Use ReadOnly Root FileSystem. Create a new Pod named my-ro-pod in Namespace application of image busybox:1.32.0. Make sure the container keeps running, like using sleep 1d. The container root filesystem should be read-only:</summary>
	
	<details><summary> Generate configuration :</summary>
		
		$ k -n application run my-ro-pod --image=busybox:1.32.0 -oyaml --dry-run=client --command -- sh -c 'sleep 1d' > my-ro-pod.yaml

	</details>

	<details><summary> Edit it to:</summary>
		
		---
		apiVersion: v1
		kind: Pod
		metadata:
		labels:
			run: my-ro-pod
		name: application
		namespace: sun
		spec:
		containers:
		- command:
			- sh
			- -c
			- sleep 1d
			image: busybox:1.32.0
			name: my-ro-pod
			securityContext:
				readOnlyRootFilesystem: true
		dnsPolicy: ClusterFirst
		restartPolicy: Always

	</details>
	
</details>

**Useful official documentation**

- [security-context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

**Useful non-official documentation**

- None


# Additional useful material


## Articles

1. [cheatsheet for kubernetes](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

## Books

1. [Aqua Security Liz Rice:Free Container Security Book](https://info.aquasec.com/container-security-book)
1. [Learn Kubernetes security: Securely orchestrate, scale, and manage your microservices in Kubernetes deployments](https://www.amazon.com/Learn-Kubernetes-Security-orchestrate-microservices/dp/1839216506)
1. [Let's Learn CKS Scenarios](https://gumroad.com/l/cksbook)

## Videos

1. [Kubernetes Security Best Practices - Ian Lewis, Google](https://youtu.be/wqsUfvRyYpw)
2. [Learn Kubernetes Security](https://www.youtube.com/playlist?list=PLeLcvrwLe1859Rje9gHrD1KEp4y5OXApB)
3. [Let's Learn Kubernetes Security](https://youtu.be/VjlvS-qiz_U)
4. [Webinar | Certified Kubernetes Security Specialist (CKS), January 2022](https://youtu.be/Qqoe-PbuQcs)

## Containers and Kubernetes Security Training

1. [Killer.sh CKS practice exam](https://killer.sh/cks)
2. [Kim Wüstkamp's on Udemy: Kubernetes CKS 2023 Complete Course - Theory - Practice](https://www.udemy.com/course/certified-kubernetes-security-specialist/)
3. [Linux Foundation Kubernetes Security essentials LFS 260](https://training.linuxfoundation.org/training/kubernetes-security-essentials-lfs260/)
4. [KodeCloud "Certified Kubernetes Security Specialist (CKS)](https://kodekloud.com/courses/certified-kubernetes-security-specialist-cks/)
5. [Falco 101](https://learn.sysdig.com/falco-101)
6. [Killer Shell CKS - Interactive Scenarios for Kubernetes Security](https://killercoda.com/killer-shell-cks)
7. [Linux Foundation Kubernetes Certifications Now Include Exam Simulator](https://training.linuxfoundation.org/announcements/linux-foundation-kubernetes-certifications-now-include-exam-simulator)


# Authors

Created and maintained by [Vitalii Natarov](https://github.com/SebastianUA). An email: [vitaliy.natarov@yahoo.com](vitaliy.natarov@yahoo.com).


# License
Apache 2 Licensed. See [LICENSE](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/blob/main/LICENSE) for full details.
