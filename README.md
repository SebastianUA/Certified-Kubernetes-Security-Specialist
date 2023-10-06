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
 - <details><summary>Example_1: Check if anonymous access is enabled (if so, - it should be disabled):</summary>
	
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "anonymous-auth"
	```
</details>

 - <details><summary>Example_2: Check if insecure port is using (if so, - it should be changed to 0):</summary>
	
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "insecure-port"
	```
</details>

 - <details><summary>Example_3: Check if Node restriction is enabled (if so, - it should NodeRestriction):</summary>
	
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "enable-admission-plugins"
	```
</details>

TBD more soon!

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
	
	```
	k create role role_name --verb=get,list,watch --resource=pods
	k create rolebinding role_name_binding --role=role_name --user=captain --group=group1
	```
</details>

 - <details><summary>Example_2: Working with RBAC (cluster roles and cluster role bindings):</summary>
	
	```
	k create clusterrole cluster_role --verb=get,list,watch --resource=pods
	k create clusterrolebinding cluster_role_binding --clusterrole=cluster_role --user=cap
	```
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
 - <details><summary>Example_1: Use Seccomp:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_2: Use AppArmor:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_3: PSA enforces:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_4: Apply host updates:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_5: Install minimal required OS fingerprint:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_6: Identify and address open ports:</summary>
	
	```
	TBD
	```
</details>

 - <details><summary>Example_7: Remove unnecessary packages:</summary>
	
	```
	TBD
	```
</details>


**Useful official documentation**

- [securing-a-cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)


### 2. Minimize IAM roles

TBD!

**Useful official documentation**

- [access-authn-authz](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)

### 3. Minimize external access to the network

TBD!

**Useful official documentation**

- [network-policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### 4. Appropriately use kernel hardening tools such as AppArmor, and SecComp

TBD!

**Useful official documentation**

- [pod-security-admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [apparmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

**Useful non-official documentation**

- [apparmor](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [Container Security](https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf?utm_medium=email&_hsmi=85733108&_hsenc=p2ANqtz--tQO3LhW0VqGNthE1dZqnfki1pYhEq-I_LU87M03pmQlvhXhA1lO4jO3vLjN4NtcbEiFyIL2lEBlzzMHe96VPXERZryw&utm_content=85733108&utm_source=hs_automation)

## Minimize Microservice Vulnerabilities - 20%

### 1. Setup appropriate OS-level security domains

TBD!

**Useful official documentation**

- None

**Useful non-official documentation**

- [opa-gatekeeper-policy-and-governance-for-kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
- [openpolicyagent](https://www.openpolicyagent.org/docs/latest/kubernetes-primer/)
- [security context for pods](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [kubernetes-security-psp-network-policy](https://sysdig.com/blog/kubernetes-security-psp-network-policy/)


### 2. Manage Kubernetes secrets

TBD! 

**Useful official documentation**

- [secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [encrypt-data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

**Useful non-official documentation**

- None

### 3. Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)

TBD!

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

TBD!

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
	
	```
	TBD
	```
</details>

**Useful official documentation**

- [admission-controllers#imagepolicywebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
- [extensible-admission-controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

**Useful non-official documentation**

- [why-do-i-need-admission-controllers](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers)


### 3. Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)

TBD!

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
	
### 4. Scan images for known vulnerabilities 

TBD!

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

TBD!

**Useful official documentation**

- None

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

TBD!

**Useful official documentation**

- [audit](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

**Useful non-official documentation**

- [kubernetes-audit-logging](https://docs.sysdig.com/en/docs/sysdig-secure/secure-events/kubernetes-audit-logging/)
- [monitor-kubernetes-audit-logs](https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/)

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
