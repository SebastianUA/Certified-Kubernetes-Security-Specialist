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
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/concepts/security/controlling-access/

	2. https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests

	3. https://kubernetes.io/docs/concepts/security/controlling-access/#api-server-ports-and-ips

	4. https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user

	5. https://kubernetes.io/docs/concepts/cluster-administration/certificates/
</details>

### 2. Use Role Based Access Controls to minimize exposure
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/reference/access-authn-authz/rbac/

	2. https://rbac.dev/

	3. https://docs.bitnami.com/tutorials/simplify-kubernetes-resource-access-rbac-impersonation/

	4. https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/01-Cluster%20Architcture%2C%20Installation%20and%20Configuration.md
</details>

### 3. Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
	2. https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
	3. https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
	4. https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules
		5. https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
	
	Update Kubernetes frequently:
	1. https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/
	2. https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/
</details>

## System Hardening - 15%
### 1. Minimize host OS footprint (reduce attack surface)
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules

</details>

### 2. Minimize IAM roles
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/reference/access-authn-authz/authentication/

</details>

### 3. Minimize external access to the network
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/concepts/services-networking/network-policies/

</details>

### 4. Appropriately use kernel hardening tools such as AppArmor, and SecComp
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/concepts/security/pod-security-admission/
	2. AppArmor:
		- https://kubernetes.io/docs/tutorials/security/apparmor/
			- https://gitlab.com/apparmor/apparmor/-/wikis/Documentation
		3. SecComp:
	 		- https://kubernetes.io/docs/tutorials/security/seccomp/
	   	4. https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf?utm_medium=email&_hsmi=85733108&_hsenc=p2ANqtz--tQO3LhW0VqGNthE1dZqnfki1pYhEq-I_LU87M03pmQlvhXhA1lO4jO3vLjN4NtcbEiFyIL2lEBlzzMHe96VPXERZryw&utm_content=85733108&utm_source=hs_automation

</details>

## Minimize Microservice Vulnerabilities - 20%
### 1. Setup appropriate OS-level security domains
<details><summary>Useful documentation</summary>

	1. PSP: 
		- https://kubernetes.io/docs/concepts/policy/pod-security-policy/
		
	2. OPA: 
		- https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
		- https://www.openpolicyagent.org/docs/latest/kubernetes-primer/
	
	3. Security Context: 
		- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
		- https://sysdig.com/blog/kubernetes-security-psp-network-policy/

</details>

### 2. Manage Kubernetes secrets
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/concepts/configuration/secret/
	2. https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/

</details>

### 3. Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
<details><summary>Useful documentation</summary>

	1. Runtime: 
		- https://kubernetes.io/docs/concepts/containers/runtime-class/
		- https://github.com/kubernetes/enhancements/blob/5dcf841b85f49aa8290529f1957ab8bc33f8b855/keps/sig-node/585-runtime-class/README.md#examples
		- https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/585-runtime-class/README.md#examples
	
	2. gVisor: 
		- https://gvisor.dev/docs/user_guide/install/
</details>

### 4. Implement pod-to-pod encryption by use of mTLS
<details><summary>Useful documentation</summary>

	1. mTLS:
		- https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/
		- https://www.istioworkshop.io/11-security/01-mtls/
	2. Istio: 
		- https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/
	
	3. Linkerd: 
		- https://linkerd.io/2/features/automatic-mtls/

</details>

## Supply Chain Security - 20% 
### 1. Minimize base image footprint
<details><summary>Useful documentation</summary>

	1. https://cloud.google.com/blog/products/containers-kubernetes/7-best-practices-for-building-containers
	2. https://learnk8s.io/blog/smaller-docker-images
	3. https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-how-and-why-to-build-small-container-images
	4. https://cloud.google.com/architecture/best-practices-for-building-containers#build-the-smallest-image-possible
	5. https://docs.docker.com/build/building/multi-stage/
	6. https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34

</details>

### 2. Secure your supply chain: whitelist allowed registries, sign and validate images
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook
	2. https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers
	3. https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
	4. https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
	5. https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/

</details>

### 3. Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)
<details><summary>Useful documentation</summary>

	1. statically analyse:
		- https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml
	2. kubehunter: 
		- https://github.com/aquasecurity/kube-hunter
	
	3. kubesec: 
		- https://kubesec.io/
	
	4. trivy:
		- https://github.com/aquasecurity/trivy
	
	5. checkov:
		- https://bridgecrew.io/blog/kubernetes-static-code-analysis-with-checkov/
	
	6. clair:
		- https://github.com/quay/clair
	
	7. kube-score:
		- https://kube-score.com/

</details>

### 4. Scan images for known vulnerabilities 
<details><summary>Useful documentation</summary>

	1. scan images and run ids:
		- https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids
	2. anchore:
		- https://github.com/anchore/anchore-cli#command-line-examples
	
	3. trivy:
		- https://github.com/aquasecurity/trivy

</details>

## Monitoring, Logging, and Runtime Security - 20%
### 1. Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/tutorials/security/seccomp/
	2. https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/
	3. https://learn.sysdig.com/falco-101
	4. https://github.com/falcosecurity/charts/tree/master/falco
	5. https://github.com/falcosecurity/charts
	6. https://falco.org/blog/detect-cve-2020-8557/

</details>

### 2. Detect threats within a physical infrastructure, apps, networks, data, users, and workloads
<details><summary>Useful documentation</summary>

	1. https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/
	2. https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/guidance-on-kubernetes-threat-modeling
	3. https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/

</details>

### 3. Detect all phases of attack regardless of where it occurs and how it spreads
<details><summary>Useful documentation</summary>

	1. https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/
	2. https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/
	3. https://www.cncf.io/online-programs/mitigating-kubernetes-attacks/
	4. https://www.optiv.com/insights/source-zero/blog/anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us
	5. https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/
	6. https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/
	7. https://www.youtube.com/watch?v=HWv8ZKLCawM&ab_channel=CNCF%5BCloudNativeComputingFoundation%5D

</details>

### 4. Perform deep analytical investigation and identification of bad actors within the environment
<details><summary>Useful documentation</summary>

	1. https://docs.sysdig.com/en/
	2. https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/
	3. https://www.youtube.com/watch?v=VEFaGjfjfyc&ab_channel=Sysdig
	4. https://www.redhat.com/en/topics/containers/kubernetes-security

</details>

### 5. Ensure immutability of containers at runtime
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/blog/2018/03/principles-of-container-app-design/
	2. https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/keeping_containers_fresh_and_updateable#leveraging_kubernetes_and_openshift_to_ensure_that_containers_are_immutable
	3. https://medium.com/sroze/why-i-think-we-should-all-use-immutable-docker-images-9f4fdcb5212f
	4. https://techbeacon.com/enterprise-it/immutable-infrastructure-your-systems-can-rise-dead
	5. ? Falco: https://falco.org/docs/
	6. ? Sysdig: https://docs.sysdig.com/

</details>

### 6. Use Audit Logs to monitor access
<details><summary>Useful documentation</summary>

	1. https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
	2. https://docs.sysdig.com/en/docs/sysdig-secure/secure-events/kubernetes-audit-logging/
	3. https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/

</details>

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
