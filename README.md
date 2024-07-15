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
- Software Version: **Kubernetes v1.30**
- [The official website with certification](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist)
- [CNCF Exam Curriculum repository](https://github.com/cncf/curriculum/)
- [Tips & Important Instructions: CKS](https://docs.linuxfoundation.org/tc-docs/certification/important-instructions-cks)
- [Candidate Handbook](https://docs.linuxfoundation.org/tc-docs/certification/lf-handbook2)
- [Verify Certification](https://training.linuxfoundation.org/certification/verify/)


# Structure of certification

## Cluster Setup - 10%

- Use network security policies to restrict cluster-level access. This will help to prevent unauthorized access to your cluster resources.
- Use the CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi). The CIS benchmark is a set of security recommendations that can help you to harden your Kubernetes cluster.
- Properly set up Ingress objects with security control. Ingress objects allow you to expose your Kubernetes services to the outside world. It is important to configure Ingress objects with appropriate security controls to prevent unauthorized access.
- Protect node metadata and endpoints. Node metadata and endpoints contain sensitive information about your Kubernetes nodes. It is important to protect this information from unauthorized access.
- Minimize use of, and access to, GUI elements. The Kubernetes GUI can be a convenient way to manage your cluster, but it is also a potential security risk. It is important to minimize use of the GUI and to restrict access to it to authorized users.
- Verify platform binaries before deploying. Before deploying Kubernetes platform binaries, it is important to verify their authenticity and integrity. This can be done by using a checksum or by signing the binaries.

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
	  - Ingress
	  - Egress
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

 - <details><summary>Example_3: Define an allow-all policy which overrides the deny all policy on <b>default</b> namespace:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: NetworkPolicy
	metadata:
		name: allow-all
		namespace: default
	spec:
	  podSelector: {}
	  policyTypes:
	  - Ingress
	  - Egress
	  ingress: {}
	  egress: {}
	```

</details>

 - <details><summary>Example_4: Create default deny networking policy for ingress only. Use netpol in <b>monitoring</b> namespace:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: NetworkPolicy
	metadata:
	  name: deny-ingress-only
	  namespace: monitoring
	spec:
	  podSelector: {}
	  policyTypes:
	  - Ingress
	```

</details>

- <details><summary>Example_5: Create default deny networking policy for egress only. Use netpol in <b>monitoring</b> namespace:</summary>
	
	```
	---
	apiVersion: networking.k8s.io/v1
	kind: NetworkPolicy
	metadata:
	  name: deny-egress-only
	  namespace: monitoring
	spec:
	  podSelector: {}
	  policyTypes:
	  - Egress
	```

</details>

Other examples you can find in [hands-on with Kubernetes network policy](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/tree/main/hands-on/01_Cluster_Setup/Kubernetes-network-policy)

**Useful official documentation**

- [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

**Useful non-official documentation**

- [Networking policy editor](https://editor.networkpolicy.io)
- [Kubernetes network policy recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)
- [An Introduction to Kubernetes Network Policies for Security People](https://reuvenharrison.medium.com/an-introduction-to-kubernetes-network-policies-for-security-people-ba92dd4c809d)
- [Testing Kubernetes network policies behavior](https://github.com/Tufin/test-network-policies/tree/master)
- [Network policy from banzaicloud](https://banzaicloud.com/blog/network-policy/)

### 2. Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

Examples:
 - <details><summary>Example_1: Fix issues that provided in CIS file (some example of the file). That file got from kube-banch output report:</summary>
	
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
	
	Run `kube-bench` command, for example - only for master host:
	```
	kube-bench run --targets master --check 1.3.2 
	```

	The output will be something like the next one:
	```
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
		image: registry.k8s.io/kube-apiserver:v1.29.2
	...
	```

</details>

**Useful official documentation**

- None 

**Useful non-official documentation**

- [CISecurity website](https://www.cisecurity.org/benchmark/kubernetes)
- [Kube-bench](https://github.com/aquasecurity/kube-bench)
- [Kube-Bench: Kubernetes CIS Benchmarking Tool](https://devopscube.com/kube-bench-guide/)
- [101 days of kubernetes](https://www.101daysofdevops.com/courses/101-days-of-kubernetes/lessons/day-1-kubesec/)

### 3. Properly set up Ingress objects with security control

Examples:
 - <details><summary>Install ingress</summary>
	
	Deploy the stack:
	```
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml
	```

	After a while, they should all be running. The following command will wait for the ingress controller pod to be up, running, and ready:
	```
	kubectl wait --namespace ingress-nginx \
	--for=condition=ready pod \
	--selector=app.kubernetes.io/component=controller \
	--timeout=120s
	```

	Let's create a simple web server and the associated service:
	```
	kubectl create deployment demo --image=httpd --port=80
	kubectl expose deployment demo
	```

	Then create an ingress resource. The following example uses a host that maps to localhost:
	```
	kubectl create ingress demo-localhost --class=nginx \

  	--rule="demo.localdev.me/*=demo:80"
  	```
  	
  	Now, forward a local port to the ingress controller:
  	```
  	kubectl port-forward --namespace=ingress-nginx service/ingress-nginx-controller 8080:80
  	```
  	
  	At this point, you can access your deployment using curl:
  	```
  	curl --resolve demo.localdev.me:8080:127.0.0.1 http://demo.localdev.me:8080
  	```
  	
  	You should see a HTML response containing text like "It works!".

</details>

 - <details><summary>Example_1: Create ingress with <b>ingress-app1</b> name in <b>app1</b> namespace for the <b>app1-svc</b> service. You should open use <b>app1</b> path as prefix</summary>
	
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
		- path: /app1
			pathType: Prefix
			backend:
			service:
				name: app1
				port:
				number: 80
	```

	Also, you can generate it through CLI:
	```
	k create ingress ingress-app1 --class=nginx --rule="*/*=app1-svc:80" --annotation="nginx.ingress.kubernetes.io/rewrite-target=/" --dry-run=client -o yaml > ingress-app1.yaml
	```

	Apply the config:
	```
	k apply -f ingress-app1.yaml
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
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt -subj "/CN=local.domail.name/O=local.domail.name"
kubectl -n app1 create secret tls local-domain-tls --key cert.key --cert cert.crt
```

**Useful official documentation**

- [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress)
- [Ingress with TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

**Useful non-official documentation**

- [How to Setup Nginx Ingress Controller On Kubernetes](https://devopscube.com/setup-ingress-kubernetes-nginx-controller/)
- [Kubernetes Ingress Tutorial For Beginners](https://devopscube.com/kubernetes-ingress-tutorial/)

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

- [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Declare Network Policy](https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/)

**Useful non-official documentation**

- [Restricting cloud metadata api access](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)
- [Kubelet authn/authz](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)


### 5. Minimize the use of and access to, GUI elements

Restricting the Kubernetes GUI can be accomplished through proper Role-Based Access Control (RBAC) configuration. In Kubernetes, RBAC is created via the RoleBinding resource. Always ensure people are given least-privilege access by default, then provide requests as the user needs them.

A second way to secure the GUI is via Token authentication. Token authentication is prioritized by the Kubernetes Dashboard. The token is in the format Authorization: Bearer `token` and it is located in the request header itself. Bearer Tokens are created through the use of Service Account Tokens. These are just a few of the K8s dashboard concepts that will wind up on the CKS. Make sure you have a thorough understanding of service accounts and how they relate to the Kubernetes Dashboard prior to taking the exam.

To install web-ui dashboard, use:
```
helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/

"kubernetes-dashboard" has been added to your repositories
```

To install web-ui dashboard, use:
```
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard

Release "kubernetes-dashboard" does not exist. Installing it now.
NAME: kubernetes-dashboard
LAST DEPLOYED: Mon Jun 24 23:10:08 2024
NAMESPACE: kubernetes-dashboard
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
*************************************************************************************************
*** PLEASE BE PATIENT: Kubernetes Dashboard may need a few minutes to get up and become ready ***
*************************************************************************************************

Congratulations! You have just installed Kubernetes Dashboard in your cluster.

To access Dashboard run:
  kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443

NOTE: In case port-forward command does not work, make sure that kong service name is correct.
      Check the services in Kubernetes Dashboard namespace using:
        kubectl -n kubernetes-dashboard get svc

Dashboard will be available at:
  https://localhost:8443
```

Let's get dashboard's resources:
```
k -n kubernetes-dashboard get pod,deploy,svc

NAME                                                        READY   STATUS              RESTARTS   AGE
pod/kubernetes-dashboard-api-fcb98d6fd-jpztk                1/1     Running             0          22s
pod/kubernetes-dashboard-auth-67d784b9c7-5fhnk              0/1     ContainerCreating   0          22s
pod/kubernetes-dashboard-kong-7696bb8c88-wg2dh              1/1     Running             0          22s
pod/kubernetes-dashboard-metrics-scraper-5485b64c47-f97ng   1/1     Running             0          22s
pod/kubernetes-dashboard-web-84f8d6fff4-kdrch               1/1     Running             0          22s

NAME                                                   READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/kubernetes-dashboard-api               1/1     1            1           22s
deployment.apps/kubernetes-dashboard-auth              0/1     1            0           22s
deployment.apps/kubernetes-dashboard-kong              1/1     1            1           22s
deployment.apps/kubernetes-dashboard-metrics-scraper   1/1     1            1           22s
deployment.apps/kubernetes-dashboard-web               1/1     1            1           22s

NAME                                           TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                         AGE
service/kubernetes-dashboard-api               ClusterIP   10.101.228.206   <none>        8000/TCP                        22s
service/kubernetes-dashboard-auth              ClusterIP   10.98.91.18      <none>        8000/TCP                        22s
service/kubernetes-dashboard-kong-manager      NodePort    10.99.35.114     <none>        8002:30410/TCP,8445:30211/TCP   22s
service/kubernetes-dashboard-kong-proxy        ClusterIP   10.98.25.235     <none>        443/TCP                         22s
service/kubernetes-dashboard-metrics-scraper   ClusterIP   10.101.105.50    <none>        8000/TCP                        22s
service/kubernetes-dashboard-web               ClusterIP   10.108.39.226    <none>        8000/TCP                        22s
```

As most of you notice, default Kubernetes Dashboard service is exposed as Cluster IP and it would not be possible for administrators to access this IP address without getting inside a shell inside a Pod. For most cases, administrators use “kubectl proxy” to proxy an endpoint within the working machine to the actual Kubernetes Dashboard service.
In some testing environments in less security concern, we could make Kubernetes Dashboard deployments and services to be exposed with Node Port, so administrators could use nodes’ IP address, public or private, and assigned port to access the service. We edit the actual running deployment YAML:
```
kubectl edit deployment kubernetes-dashboard-web -n kubernetes-dashboard
```

Then, add `--insecure-port=9999` and tune it, likes:
```
.....
spec:
    containers:
    - args:
      - --namespace=kubernetes-dashboard
      - --insecure-port=9999
	image: docker.io/kubernetesui/dashboard-web:1.4.0
	imagePullPolicy: Always
	livenessProbe:
		failureThreshold: 3
		httpGet:
			path: /
			port: 9999
			scheme: HTTP
		initialDelaySeconds: 30
		periodSeconds: 10
		successThreshold: 1
		timeoutSeconds: 30
.....
```

NOTE: 
- Delete the `auto-generate-certificates` from config.
- Change `port` of `livenessProbe`  to `9999`.
- Change `scheme` of `livenessProbe` to `HTTP`.

After that, we make changes on Kubernetes Dashboard services:
```
kubectl edit service kubernetes-dashboard-web -n kubernetes-dashboard
```

And:
- Change port to `9999`.
- Change targetPort to `9999`.
- Change type to `NodePort`.

The config should be likes:
```
.....
ports:
  - nodePort: 30142
    port: 9999
    protocol: TCP
    targetPort: 9999
  selector:
    k8s-app: kubernetes-dashboard
  sessionAffinity: None
  type: NodePort
.....
```
Then, runnning the next command to forward port to:
```
kubectl port-forward deployments/kubernetes-dashboard 9999:30142 -n kubernetes-dashboard
```

Open your browser on `http://127.0.0.1:30142/`.
Since Kubernetes Dashboard is leveraging service account “default” in namespace “kubernetes-dashboard” for accessing each resource, binding the right permission to this service account would allow the dashboard to show more information in the corresponding namespaces.

**Useful official documentation**

- [Web UI dashboard](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)

**Useful non-official documentation**

- [On securing the kubernetes dashboard](https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca)
- [Kubernetes dashboards](https://www.airplane.dev/blog/intro-to-kubernetes-dashboards)

### 6. Verify platform binaries before deploying

In this section, we will take a look at Verify platform binaries before deploying.

Examples:
 - <details><summary>Compare binary file of kubelet on the current host and with kubelet 1.27 that you must download from official release:</summary>
	
	```
	sha512sum $(which kubelet) | cut -c-10
	wget -O kubelet https://dl.k8s.io/$(/usr/bin/kubelet --version | cut -d " " -f2)/bin/linux/$(uname -m)/kubelet 
	sha512sum ./kubelet | cut -c -10
	```

</details>

 - <details><summary>Compare binary file of kubectl on the current host and with kubectl 1.30 that you must download from official release. The 2d example:</summary>
	
	Download SHA256 of kubelet:
	```
	curl -LO "https://dl.k8s.io/v1.30.0/bin/linux/amd64/kubectl.sha256"
	```

	Checking SHA with current kubectl that has been installed on host:
	```
	echo "$(cat kubectl.sha256)  $(which kubectl)" | shasum -a 256 --check
	/usr/bin/kubectl: OK
	```

	NOTE: The same way is for `kubeadm` and `kubelet`.

</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [Kubernetes releases](https://github.com/kubernetes/kubernetes/releases)


## Cluster Hardening - 15%

### 1. Restrict access to Kubernetes API

When it comes to Kubernetes Production Implementation restricting API access is very important. Restricting access to the API server is about three things:
- Authentication in Kubernetes.
- Authorization in Kubernetes.
- Admission Control The primary topics under this section would be bootstrap tokens, RBAC, ABAC, service account, and admission webhooks.
- Cluster API access methods.
- Kubernetes API Access Security.
- Admission Controllers in Kubernetes.
- Admission Webhooks in Kubernetes.

Examples:
 - <details><summary>Example_1: Blocking anonymous access to use API in Kubelet:</summary>

	Checking, where the config is:
	```
	ps -ef | grep kubelet | grep -Ei "kubeconfig"
	```

	<details><summary>Fix if it's enabled, oppening /var/lib/kubelet/config.yaml file:</summary>
	
		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		authentication:
		anonymous:
			enabled: false
		............
	</details>

	NOTE: As workaround, you can use the `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` file and add `--anonymous-auth=false` into `KUBELET_SYSTEM_PODS_ARGS` if kubelet in your cluster using kubeadm.
	
	Make restart service of kubelet:
	```
	systemctl daemon-reload && \
	systemctl restart kubelet.service
	```
	

</details>

 - <details><summary>Example_2: Changing authentication mode to Webhook for kubelet:</summary>
	
	Getting `kubeconfig` path:
	```
	ps -ef | grep kubelet | grep -Ei "kubeconfig"
	```

	<details><summary>Oppening /var/lib/kubelet/config.yaml file:</summary>
	
		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		.....
		authorization:
			mode: Webhook
		.....

	</details>

	Make restart service of kubelet:
	```
	systemctl daemon-reload && systemctl restart kubelet.service
	```

</details>

 - <details><summary>Example_3: Blocking insecure port for kube-apiserver:</summary>

	First, checking:
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "insecure-port"
	```

	<details><summary>Oppening /etc/kubernetes/manifests/kube-apiserver.yaml file:</summary>
	
		---
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
			............
			- --insecure-port=0
			- --secure-port=443
			.........

	</details>
	

</details>

 - <details><summary>Example_4: Enable protect kernel defaults for kube-apiserver:</summary>

	First, checking:
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "protect-kernel-defaults"
	```

	So, we can put `protectKernelDefaults` parameter into `kubelet`, but first of all, check where the configuration is:
	```
	ps -ef | grep kubelet | grep -Ei "config"
	```

	<details><summary>Oppening /var/lib/kubelet/config.yaml file:</summary>

		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		authentication:
		anonymous:
			enabled: false
		webhook:
			cacheTTL: 0s
			enabled: true
		x509:
			clientCAFile: /etc/kubernetes/pki/ca.crt
		authorization:
		mode: Webhook
		webhook:
			cacheAuthorizedTTL: 0s
			cacheUnauthorizedTTL: 0s
		cgroupDriver: systemd
		protectKernelDefaults: true
		.........
	</details>

	NOTE: As workaround, you can use the `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` file and add `--protect-kernel-defaults=true` into `KUBELET_SYSTEM_PODS_ARGS` if kubelet in your cluster using kubeadm.
	
	Make restart service of kubelet after your change(s):
	```
	systemctl daemon-reload && systemctl restart kubelet.service
	```
	

</details>

 - <details><summary>Example_5: NodeRestriction enabling:</summary>

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
    k label node controlplane controlplane/two=123 # restricted
    k label node node01 node-restriction.kubernetes.io/two=123 # restricted
    k label node node01 test/two=123 # works
	```

	*NOTE*: If you don't know how to find proper parameter (at that case - NodeRestriction), you can use:
	```
	ps -ef | grep apiserver
	```
	Getting plugins:
	```
	/proc/15501/exe -h | grep -Ei plugins
	```
	Where `15501` - PID ID of the process. 

</details>

- <details><summary>Example_6: Kubernetes API troubleshooting:</summary>

	1. First al all, checking:
	```
	cat /var/log/syslog | grep kube-apiserver
	```	
	Or, better try to find line with error:
	```	
	cat /var/log/syslog | grep -Ei "apiserver" | grep -Ei "line"
	```
	
	2. Secondly, checking:
	```
	journalctl -xe | grep apiserver
	```

	3. Lastly, getting ID of container:
	```
	crictl ps -a | grep api
	```

	Check logs:
	```
	crictl logs fbb80dac7429e
	```

	Where:
	- `fbb80dac7429e` - ID of container.
	
</details>

- <details><summary>Example_7: Certificate signing requests sign manually:</summary>

	First of all, we should have key. Let's get it through openssl:
	```
	openssl genrsa -out iuser.key 2048
	```

	Next, runnning the next command to generate certificate:
	```
	openssl req -new -key iuser.key -out iuser.csr
	```

	Note: set `Common Name` to `iuser@internal.users`

	<details><summary>Certificate signing requests sign manually (manually sign the CSR with the K8s CA file to generate the CRT):</summary>
	
		openssl x509 -req -in iuser.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out iuser.crt -days 500

	</details>

	<details><summary>Set credentials & context:</summary>
	
		k config set-credentials iuser@internal.users --client-key=iuser.key --client-certificate=iuser.crt
		k config set-context iuser@internal.users --cluster=kubernetes --user=iuser@internal.users
		k config get-contexts
		k config use-context iuser@internal.users

	</details>

	<details><summary>Checks:</summary>
	
		k get ns
		
		k get po

	</details>

</details>

- <details><summary>Example_8: Certificate signing requests sign K8S:</summary>

	First of all, we should have key. Let's get it through openssl:
	```
	openssl genrsa -out iuser.key 2048
	```

	Next, runnning the next command to generate certificate:
	```
	openssl req -new -key iuser.key -out iuser.csr
	```

	Note: set Common Name = iuser@internal.users

	Convert the CSR file into base64:
	```
	cat iuser.csr | base64 -w 0
	```
	
	<details><summary>Copy it into the YAML:</summary>
	
		apiVersion: certificates.k8s.io/v1
		kind: CertificateSigningRequest
		metadata:
		name: iuser@internal.users # ADD
		spec:
		groups:
			- system:authenticated
		request: CERTIFICATE_BASE64_HERE
		signerName: kubernetes.io/kube-apiserver-client
		usages:
			- client auth

	</details>

	Create and approve:
	```
	k -f csr.yaml create
		
	k get csr
		
	k certificate approve iuser@internal.users
	```

	Now, check the status one more time (should be `approved`):
	```
	k get csr
	```

	Download signed certificate:
	```
	k get csr iuser@internal.users -ojsonpath="{.status.certificate}" | base64 -d > iuser.crt
	```

	Now, set credentials & context:
	```
	k config set-credentials iuser@internal.users --client-key=iuser.key --client-certificate=iuser.crt
	k config set-context iuser@internal.users --cluster=kubernetes --user=iuser@internal.users
	k config get-contexts
	k config use-context iuser@internal.users
	```

	Checks:
	```
	k get ns && k get po
	```

</details>

- <details><summary>Example_9: Add minimal TLS 1.2 for ETCD and kube-apiserver; Add TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 cipher as well:</summary>

	- ETCD side, open `/etc/kubernetes/manifests/etcd.yaml` file and put the next:
		```
		....
		spec:
			containers:
			- command:
			- etcd
			- --advertise-client-urls=https://172.30.1.2:2379
			- --cert-file=/etc/kubernetes/pki/etcd/server.crt
			- --client-cert-auth=true
			- --data-dir=/var/lib/etcd
			- --experimental-initial-corrupt-check=true
			- --experimental-watch-progress-notify-interval=5s
			- --initial-advertise-peer-urls=https://172.30.1.2:2380
			- --initial-cluster=controlplane=https://172.30.1.2:2380
			- --key-file=/etc/kubernetes/pki/etcd/server.key
			- --listen-client-urls=https://127.0.0.1:2379,https://172.30.1.2:2379
			- --listen-metrics-urls=http://127.0.0.1:2381
			- --listen-peer-urls=https://172.30.1.2:2380
			- --name=controlplane
			- --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
			- --peer-client-cert-auth=true
			- --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
			- --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
			- --snapshot-count=10000
			- --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
			- --cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			- --tls-min-version=TLS1.2
			image: registry.k8s.io/etcd:3.5.7-0
			imagePullPolicy: IfNotPresent
		....
		```

		Checking ETCD:
		```
		crictl ps -a | grep etcd
		```

		NOTE: To get logs, you can use:
		```
		cat /var/log/syslog | grep etcd
		```

		To check cipher:
		```
		nmap --script ssl-enum-ciphers -p 2379 127.0.0.1
		```

	- kube-apiserver side, open `/etc/kubernetes/manifests/kube-apiserver.yaml` file and put the next:
		```
		- --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		- --tls-min-version=VersionTLS12
		```

		Checking kube-apiserver:
		```
		crictl ps -a | grep apiserver
		```

		NOTE: To get logs, you can use:
		```
		cat /var/log/syslog | grep apiserver
		```

		To check cipher:
		```
		nmap --script ssl-enum-ciphers -p 6443 127.0.0.1
		```
	
	- kubelet side, open `/var/lib/kubelet/config.yaml` file and put the next:
		```
		apiVersion: kubelet.config.k8s.io/v1beta1
		authentication:
		anonymous:
			enabled: false
		webhook:
			cacheTTL: 0s
			enabled: true
		x509:
			clientCAFile: /etc/kubernetes/pki/ca.crt
		authorization:
		mode: Webhook
		webhook:
			cacheAuthorizedTTL: 0s
			cacheUnauthorizedTTL: 0s
		cgroupDriver: systemd
		clusterDNS:
		- 10.96.0.10
		clusterDomain: cluster.local
		tlsCipherSuites:
		- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		tlsMinVersion: VersionTLS12
		```
		
		Reload daemon:
		```
		systemctl daemon-reload
		```

		Restart kubelet service:
		```
		systemctl restart kubelet.service
		```

		Checking kube-apiserver:
		```
		systemctl status start kubelet.service
		```

		To check cipher:
		```
		nmap --script ssl-enum-ciphers -p 10250 127.0.0.1
		```

		NOTE: I'm note sure that it's needing to do.

</details>

 - <details><summary>Example_10: Enable readOnlyPort for kubelet:</summary>

	First of all, check where the configuration is:
	```
	ps -ef | grep kubelet | grep -Ei "config"
	```

	<details><summary>Oppening `/var/lib/kubelet/config.yaml` file:</summary>

		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		authentication:
		anonymous:
			enabled: false
		webhook:
			cacheTTL: 0s
			enabled: true
		x509:
			clientCAFile: /etc/kubernetes/pki/ca.crt
		authorization:
		mode: Webhook
		webhook:
			cacheAuthorizedTTL: 0s
			cacheUnauthorizedTTL: 0s
		cgroupDriver: systemd
		readOnlyPort: 0
		.........
	</details>

	NOTE: As workaround, you can use the `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` file and add `–-read-only-ports=0` into `KUBELET_SYSTEM_PODS_ARGS` if kubelet in your cluster using kubeadm.
	
	Make restart service of kubelet after your change(s):
	```
	systemctl daemon-reload && systemctl restart kubelet.service
	```

</details>

 - <details><summary>Example_11: Enable rotation of certificates for kubelet:</summary>

	Getting `kubeconfig` path, for example you can use:
	```
	ps -ef | grep kubelet | grep -Ei "kubeconfig"
	```

	<details><summary>Oppening `/var/lib/kubelet/config.yaml` file:</summary>
	
		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		.....
		rotateCertificates: true
		.....

	</details>

	Make restart service of kubelet:
	```
	systemctl daemon-reload && systemctl restart kubelet.service
	```

</details>

 - <details><summary>Example_12: Blocking anonymous access to use API in kube-apiserver and getting clusterrolebindings and rolebindings:</summary>
	
	You can check it like:
	```
	ps -ef | grep kube-apiserver
	```

	First that need to check is:
	```
	cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -Ei "anonymous-auth"
	```

	*NOTE*: `--anonymous-auth` argument shows as `false`. This setting ensures that requests not rejected by other authentication methods are not treated as anonymous and therefore allowed against policy.

	Open `/etc/kubernetes/manifests/kube-apiserver.yaml` file and adding the `--anonymous-auth=false` parameter, something like:
	```
	---
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
		- --anonymous-auth=false
		........
	```

	Identify affected resources. Also, a review of RBAC items for clusterrolebindings which provide access to `system:anonymous` or `system:unauthenticated` will help, this can be done using a command like:
	```
	kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects? // [] | any(.kind == "User" and .name == "system:anonymous" or .kind == "Group" and .name == "system:unauthenticated"))'
	```

	Similarly for RoleBindings, the following command can be used:
	```
	kubectl get rolebindings -A -o json | jq '.items[] | select(.subjects? // [] | any(.kind == "User" and .name == "system:anonymous" or .kind == "Group" and .name == "system:unauthenticated"))'
	```

	As workaround, use `jsonpath` examples:
	```
	kubectl get rolebinding,clusterrolebinding -A -o jsonpath='{range .items[?(@.subjects[0].name == "system:anonymous")]}'{.roleRef.name}
	kubectl get rolebinding,clusterrolebinding -A -o jsonpath='{range .items[?(@.subjects[0].name == "system:unauthenticated")]}' - {.roleRef.name}
	```

	Super minimal style, however - not fully finished:
	```
	kubectl get rolebinding,clusterrolebinding -A -o yaml | grep -Ei 'anonymous|unauthenticated'
	kubectl get rolebinding,clusterrolebinding -A -ojson | grep -Ei 'anonymous|unauthenticated' -A15 -B10
	```

	If needed, you can delete them!
	

</details>

- <details><summary>Example_13: Read-only port for kubelet:</summary>

	Getting `kubeconfig` path, for example you can use:
	```
	ps -ef | grep kubelet | grep -Ei "kubeconfig"
	```

	<details><summary>Oppening `/var/lib/kubelet/config.yaml` file:</summary>
	
		---
		apiVersion: kubelet.config.k8s.io/v1beta1
		authentication:
		anonymous:
			enabled: false
		webhook:
			cacheTTL: 0s
			enabled: true
		x509:
			clientCAFile: /etc/kubernetes/pki/ca.crt
		authorization:
		mode: Webhook
		webhook:
			cacheAuthorizedTTL: 0s
			cacheUnauthorizedTTL: 0s
		readOnlyPort:0
		.....
	</details>

	Kubelet uses two ports:
	- `10250`: Serves API that allows full access
	- `10255`: Servers API that allow unauthenticated read-only access

	Make restart service of kubelet:
	```
	systemctl daemon-reload && systemctl restart kubelet.service
	```

</details>

**Useful official documentation**

- [Controlling access](https://kubernetes.io/docs/concepts/security/controlling-access/)
- [Controlling access (api server ports and ips)](https://kubernetes.io/docs/concepts/security/controlling-access/#api-server-ports-and-ips)
- [Block anonymous requests](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
- [Certificates](https://kubernetes.io/docs/tasks/administer-cluster/certificates/)
- [Certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)
- [Using Node Authorization](https://kubernetes.io/docs/reference/access-authn-authz/node/)
- [Accessing the Kubernetes API from a Pod](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/)
- [Access to Kubernetes cluster API](https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/)
- [Authorization Modes](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Extensible admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubelet authn/authz](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubelet config](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)

**Useful non-official documentation**

- [Attacking Kubernetes clusters using the kubelet API](https://faun.pub/attacking-kubernetes-clusters-using-the-kubelet-api-abafc36126ca)
- [Limiting access to Kubernetes resources with RBAC](https://learnk8s.io/rbac-kubernetes)
- [Let's talk about anonymous access to Kubernetes](https://raesene.github.io/blog/2023/03/18/lets-talk-about-anonymous-access-to-Kubernetes/)

### 2. Use Role Based Access Controls to minimize exposure

Allowing unnecessary cluster-wide access to everyone is a common mistake done during Kubernetes implementations. With Kubernetes RBAC, you can define fine-grained control on who can access the Kubernetes API to enforce the principle of least privilege. The concepts will include:

- Role = the position that could perform actions
- ClusterRoles = the position that could perform actions across the whole cluster
- RoleBinding = the position that could perform actions
- ClusterRoleBindings = the binding of user/service account and cluster roles

Examples:
 - <details><summary>Example_1: Working with RBAC (roles and role bindings):</summary>

	Create role & rolebinding:
	```
	k create role role_name --verb=get,list,watch --resource=pods
	k create rolebinding role_name_binding --role=role_name --user=captain --group=group1
	```

	Verify:
	```
	k auth can-i get pods --as captain -n kube-public
	k auth can-i list pods --as captain -n default
	```

</details>

 - <details><summary>Example_2: Working with RBAC (cluster roles and cluster role bindings):</summary>

	Create clusterrole & clusterrolebinding:
	```
	k create clusterrole cluster_role --verb=get,list,watch --resource=pods
	k create clusterrolebinding cluster_role_binding --clusterrole=cluster_role --user=cap
	```
	
	Verify:
	```
	k auth can-i list pods --as cap -n kube-public
	k auth can-i list pods --as cap -n default
	```

</details>

 - <details><summary>Example_3: Working with Service Account and RBAC:</summary>

	Create Service Account and RBAC:
	```
	k -n name_space_1 create sa ser_acc
	k create clusterrolebinding ser_acc-view --clusterrole view --serviceaccount name_space_1:ser_acc
	```

	Where: 
	- `name_space_1` - NS name.
	- `ser_acc` - Service account name.

	Verify:
	```
	k auth can-i update deployments --as system:serviceaccount:name_space_1:ser_acc -n default
	k auth can-i update deployments --as system:serviceaccount:name_space_1:ser_acc -n name_space_1
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

- [Advocacy site for Kubernetes RBAC](https://rbac.dev/)
- [Simplify Kubernetes resource access rbac impersonation](https://docs.bitnami.com/tutorials/simplify-kubernetes-resource-access-rbac-impersonation/)
- [Manage Role Based Access Control (RBAC)](https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/01-Cluster%20Architcture,%20Installation%20and%20Configuration.md#manage-role-based-access-control-rbac)

### 3. Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

Examples:
 - <details><summary>Example_1: Opt out of automounting API credentials for a service account (Opt out at service account scope):</summary>
	
	```
	---
	apiVersion: v1
	kind: ServiceAccount
	automountServiceAccountToken: false
	metadata:
	  name: build-robot
	  namespace: default
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

 - <details><summary>Example_3: Disable automountServiceAccountToken on namespace side:</summary>
	
	```
	---
	apiVersion: v1
	kind: Namespace
	metadata:
	creationTimestamp: "2023-10-04T20:43:49Z"
	labels:
		kubernetes.io/metadata.name: default
	name: default
	automountServiceAccountToken: false
	resourceVersion: "36"
	uid: 7d0191eb-7187-4de9-90af-59121a4a9834
	spec:
		finalizers:
			- kubernetes
	status:
		phase: Active
	```

</details>

**Useful official documentation**

- [Authorization Modes](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules)
- [Use the default service account to access the API server](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)
- [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Default roles and role bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)

**Useful non-official documentation**

- [Advocacy site for Kubernetes RBAC](https://rbac.dev/)

You must know to how:
- To create service account and greant it with some permission.
- To find needed resources and change/add permissions.

### 4. Update Kubernetes frequently

There may be an upgrade question as the documentation about upgrading with kubeadm has been significantly better in recent releases. Also, you should have mechanisms to validate the cluster components, security configurations, and application status post-upgrade.

Examples:
 - <details><summary>Example_1: K8S upgrades (Controlplane):</summary>
	
	First of all, draing the node:
	```
	k drain master --ignore-deamonsets
	```

	Update OS:
	```
	apt update -y
	```
	Install packages:
	```
	apt-cache show kubeadm | grep 1.22
	apt install kubeadm=1.22.5-00 kubelet=1.22.5-00 kubectl=1.22.5-00
	```

	Applying updates:
	```
	kubeadm upgrade plan
	kubeadm upgrade apply v1.22.5
	```

	Adding master workloads back:
	```
	k uncordon master
	```

</details>

 - <details><summary>Example_2: K8S upgrades (Nodes):</summary>
	
	First of all, draing the node:
	```
	k drain node --ignore-deamonsets
	```

	Update OS:
	```
	apt update -y
	```

	Install packages:
	```
	apt-cache show kubeadm | grep 1.22
	apt install kubeadm=1.22.5-00 kubelet=1.22.5-00 kubectl=1.22.5-00
	```
	
	Upgrade node with kubeadm:
	```
	kubeadm upgrade node
	```

	Restart service:
	```
	service kubelet restart
	```

	Then, adding master back:
	```
	k uncordon node
	```

</details>

**Useful official documentation**

- [Upgrade a cluster](https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/)
- [Kubeadm upgrade guidance](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)
- [Upgrading Kubernetes clusters using kubeadm](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)

**Useful non-official documentation**

- None 

You must know to how:
- Upgrade the K8S clusters


## System Hardening - 15%

### 1. Minimize host OS footprint (reduce attack surface)

Examples:
 - <details><summary>Example_1: Use Seccomp:</summary>
	
	By default, the folder for seccomp is located in the `/var/lib/kubelet/seccomp` location.

	Checking if seccomp is on host:
	```
	grep -i seccomp /boot/config-$(uname -r)
	
	CONFIG_SECCOMP=y
	CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
	CONFIG_SECCOMP_FILTER=y
	```

	Open `/var/lib/kubelet/seccomp/custom.json` file and put the next:
	```
	{
		"defaultAction": "SCMP_ACT_ERRNO",
		"architectures": [
			"SCMP_ARCH_X86_64",
			"SCMP_ARCH_X86",
			"SCMP_ARCH_X32"
		],
		"syscalls": [
			{
				"name": "accept",
				"action": "SCMP_ACT_ALLOW",
				"args": []
			},
			{
				"name": "uname",
				"action": "SCMP_ACT_ALLOW",
				"args": []
			},
			{
				"name": "chroot",
				"action": "SCMP_ACT_ALLOW",
				"args": []
			}
		]
	}
	```

	Going to start using seccomp with pod, for example:
	```
	---
	apiVersion: v1
	kind: Pod
	metadata:
	name: app1
	namespace: app1
	spec:
	containers:
	- image: nginx
	  name: app1
	  securityContext:
		seccompProfile:
			type: Localhost
			localhostProfile: custom.json
	```

</details>

 - <details><summary>Example_2: Use AppArmor:</summary>
	
	Get AppArmor profiles:
	```
	apparmor_status
	```

	Or, run this:
	```
	aa-status | grep some_apparmor_profile_name
	```

	Load AppArmor profile:
	```
	apparmor_parser -q apparmor_config
	```

</details>

 - <details><summary>Example_3: PSA enforces:</summary>
	
	```
	Pod Security admissions (PSA) support has been added for clusters with Kubernetes v1.23 and above. PSA defines security restrictions for a broad set of workloads and replace Pod Security Policies in Kubernetes v1.25 and above. The Pod Security Admission controller is enabled by default in Kubernetes clusters v1.23 and above. To configure its default behavior, you must provide an admission configuration file to the kube-apiserver when provisioning the cluster.
	```

</details>

 - <details><summary>Example_4: Apply host updates:</summary>
	
	```
	sudo apt update && sudo apt install unattended-upgrades -y
	systemctl status unattended-upgrades.service
	```

</details>

 - <details><summary>Example_5: Install minimal required OS fingerprint:</summary>
	
	```
	It is best practice to install only the packages you will use because each piece of software on your computer could possibly contain a vulnerability. Take the opportunity to select exactly what packages you want to install during the installation. If you find you need another package, you can always add it to the system later.
	```

</details>

 - <details><summary>Example_6: Identify and address open ports:</summary>

	1. Using lsof command and check if 8080 is open or not:
	```
	lsof -i :8080
	```

	Check where the file is:
	```
	ls -l /proc/22797/exe
	```

	To remove file:
	```
	rm -f /usr/bin/app1
	```

	Now, kill the `8080` port:
	```
	kill -9 22797
	```

	2. Using netstat command - check if `66` is oppen and kill the process and delete the binary:

	Install `netstat` on Ubuntu:
	```
	apt install net-tools
	```

	Getting process (the port is 66):
	```
	netstat -natpl | grep 66
	```

	Check where the file located:
	```
	ls -l /proc/22797/exe
	```

	To remove file, use:
	```
	rm -f /usr/bin/app1
	```

	Now, kill that port:
	```
	kill -9 22797
	```

</details>

 - <details><summary>Example_7: Remove unnecessary packages. For example, find and delete apache2 package on the host:</summary>
	
	Check details of the package:
	```
	apt show httpd
	```

	Simple output:
	```
	Package: apache2
	Version: 2.4.41-4ubuntu3.17
	Priority: optional
	Section: web
	Origin: Ubuntu
	Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
	Original-Maintainer: Debian Apache Maintainers <debian-apache@lists.debian.org>
	Bugs: https://bugs.launchpad.net/ubuntu/+filebug
	Installed-Size: 544 kB
	Provides: httpd, httpd-cgi
	Pre-Depends: dpkg (>= 1.17.14)
	Depends: apache2-bin (= 2.4.41-4ubuntu3.17), apache2-data (= 2.4.41-4ubuntu3.17), apache2-utils (= 2.4.41-4ubuntu3.17), lsb-base, mime-support, perl:any, procps
	Recommends: ssl-cert
	Suggests: apache2-doc, apache2-suexec-pristine | apache2-suexec-custom, www-browser, ufw
	Conflicts: apache2.2-bin, apache2.2-common
	Breaks: libapache2-mod-proxy-uwsgi (<< 2.4.33)
	Replaces: apache2.2-bin, apache2.2-common, libapache2-mod-proxy-uwsgi (<< 2.4.33)
	Homepage: https://httpd.apache.org/
	Task: lamp-server
	Download-Size: 95.5 kB
	APT-Manual-Installed: yes
	APT-Sources: http://archive.ubuntu.com/ubuntu focal-updates/main amd64 Packages
	Description: Apache HTTP Server
	The Apache HTTP Server Project's goal is to build a secure, efficient and
	extensible HTTP server as standards-compliant open source software. The
	result has long been the number one web server on the Internet.
	.
	Installing this package results in a full installation, including the
	configuration files, init scripts and support scripts.
	
	N: There is 1 additional record. Please use the '-a' switch to see it
	```

	Remove `apache2` pkg:
	```
	apt remove apache2 -y
	```

</details>

 - <details><summary>Example_8: Find service that runs on the host and stop it. For example, find and stop httpd service on the host:</summary>
	
	First of all, check status of the service:
	```
	service httpd status
	```

	Then, to stop service use:
	```
	service httpd stop
	```

	One more check:
	```
	service httpd status
	```

</details>

 - <details><summary>Example_9: Working with users (Create, delete, add user to needed groups. Grant some permission):</summary>
	
	To get all users on host:
	```
	cat /etc/passwd
	```

	If you want to display only the username you can use either awk or cut commands to print only the first field containing the username:
	```
	awk -F: '{print $1}' /etc/passwd
	
	cut -d: -f1 /etc/passwd
	```
	
	The /etc/group file contains information on all local user groups configured on a Linux machine. With the /etc/group file, you can view group names, passwords, group IDs, and members associated with each group:
	```
	cat /etc/group
	```

	If you want to get goups of specific use:
	```
	groups root
	```

	Creating group:
	```
	groupadd developers
	```

	Creating user:
	```
	useradd -u 1005 -g mygroup test_user
	```

	Add a User to Multiple Groups:
	```
	usermod -a -G admins,mygroup,developers test_user
	```

	Add a User with a Specific Home Directory, Default Shell, and Custom Comment:
	```
	useradd -m -d /var/www/user1 -s /bin/bash -c "Test user 1" -U user1
	```

</details>

 - <details><summary>Example_10: Working with kernel modules on the host (get, load, unload, etc):</summary>
	
	To get all modules, use:
	```
	lsmod
	```

	Or: 
	```
	lsmod | grep ^pppol2tp && echo "The module is loaded" || echo "The module is not loaded"
	```

	Also, you can use:
	```
	cat /proc/modules
	```

	Loading a Module:
	```
	modprobe wacom
	```

	You can blacklisting a module, open the file `/etc/modprobe.d/blacklist.conf` and put:
	```
	blacklist evbug
	```

</details>

 - <details><summary>Example_11: Working with UFW on Linux:</summary>
	
	To allow 22 port:
	```
	ufw allow 22
	```

	To close an opened port:
	```
	ufw deny 22
	```

	It is also possible to allow access from specific hosts or networks to a port. The following example allows SSH access from host 192.168.0.2 to any IP address on this host:
	```
	ufw allow proto tcp from 192.168.0.2 to any port 22
	```

	To see the firewall status, enter:
	```
	ufw status
	ufw status verbose
	ufw status numbered
	```

	Enamble UFW service on Linux host:
	```
	ufw enable
	```

</details>

- <details><summary>Example_12: SSH Hardening:</summary>
	
	Going to add some restriction in `/etc/ssh/sshd_config` file:
	Disable SSH for root Account `PermitRootLogin no`
	Disable password login `PasswordAuthentication no`

	Restart SSHD restart:
	```
	service sshd restart
	```

</details>

**Useful official documentation**

- [Securing a cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)

**Useful non-official documentation**

- [How to keep ubuntu-20-04 servers updated](https://www.digitalocean.com/community/tutorials/how-to-keep-ubuntu-20-04-servers-updated)
- [Enforce standards namespace labels](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)
- [Psa label enforcer policy](https://github.com/kubewarden/psa-label-enforcer-policy)
- [Migrating from pod security policies a comprehensive guide part 1 transitioning to psa](https://hackernoon.com/migrating-from-pod-security-policies-a-comprehensive-guide-part-1-transitioning-to-psa)
- [Using kyverno with pod security admission](https://kyverno.io/blog/2023/06/12/using-kyverno-with-pod-security-admission/)
- [Add psa labels](https://kyverno.io/policies/psa/add-psa-labels/add-psa-labels/)
- [Pod security admission](https://rke.docs.rancher.com/config-options/services/pod-security-admission)
- [Pod security standards](https://www.eksworkshop.com/docs/security/pod-security-standards/)
- [Implementing Pod Security Standards in Amazon EKS](https://aws.amazon.com/blogs/containers/implementing-pod-security-standards-in-amazon-eks/)
- [Seccomp profiles](https://medium.com/@LachlanEvenson/managing-kubernetes-seccomp-profiles-with-security-profiles-operator-c768cff58b0)

### 2. Minimize IAM roles

IAM roles control access to cloud resources. It is important to minimize the permissions granted to IAM roles.
Don’t use the root user, and set users with least privileges principle. Assign permissions to groups, and no to users, and assign the user to a group.

**Useful official documentation**

- None

**Useful non-official documentation**

- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### 3. Minimize external access to the network

The less exposure your system has to the outside world, the less vulnerable it is. Restrict network access to your system to only what is necessary.

Also, implement Network Policies - [hands-on with Kubernetes network policy](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/tree/main/hands-on/01_Cluster_Setup/Kubernetes-network-policy)

**Useful official documentation**

- [Networking of Kubernetes](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

**Useful non-official documentation**

- None

### 4. Appropriately use kernel hardening tools such as AppArmor, and Secсomp

Examples:
 - <details><summary>Example_1: Working with Apparmor:</summary>
	
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
				container.apparmor.security.beta.kubernetes.io/pod-with-apparmor: localhost/docker-default
			spec:
			containers:
			- image: httpd:latest
				name: pod-with-apparmor

	</details>

	Apply the prepared configuration file:
	```
	k apply -f pod-with-apparmor.yaml
	```

	Getting ID of container:
	```
	crictl ps -a | grep pod-with-apparmor
	```

	Then, run the command:
	```
	crictl inspect e428e2a3e9324 | grep apparmor
		"apparmor_profile": "localhost/docker-default"
    	"apparmorProfile": "docker-default",
	```
	</details>

- <details><summary>Example_2: Working with Seccomp:</summary>

	The example is already described in `Minimize host OS footprint (reduce attack surface)` section.

</details>

**Useful official documentation**

- [Pod security admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Apparmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [Seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Set the Seccomp Profile for a Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-seccomp-profile-for-a-container)
- [Securing a Pod](https://kubernetes.io/docs/tutorials/security/apparmor/#securing-a-pod)

**Useful non-official documentation**

- [Apparmor](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [Container Security](https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf?utm_medium=email&_hsmi=85733108&_hsenc=p2ANqtz--tQO3LhW0VqGNthE1dZqnfki1pYhEq-I_LU87M03pmQlvhXhA1lO4jO3vLjN4NtcbEiFyIL2lEBlzzMHe96VPXERZryw&utm_content=85733108&utm_source=hs_automation)

### 5. Principle of least privilege

Run containers as non-root users: Specify a non-root user in your Dockerfile or create a new user with limited privileges to reduce the risk of container breakout attacks.

Avoid privileged containers: Don’t run privileged containers with unrestricted access to host resources. Instead, use Linux kernel capabilities to grant specific privileges when necessary.

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
	

</details>

 - <details><summary>Example_2: Working with Privileged containers:</summary>
	
	Run a pod through CLI:
	```	
	k run privileged-pod --image=nginx:alpine --privileged
	```

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

	*NOTE*: When you set runAsNonRoot: true you require that the container will run with a user with any UID other than 0. No matter which UID your user has. So, that parameter must set to `false` for security context.
	

</details>

- <details><summary>Example_3: Working with non-root user in containers (runAsNonRoot):</summary>
	
	```
	k run non-root-pod --image=nginx:alpine --dry-run=client -o yaml > non-root-pod.yaml
	```

	<details><summary> Edit that non-root-pod.yaml file to:</summary>
	
		---
		apiVersion: v1
		kind: Pod
		metadata:
			labels:
				run: non-root-pod
			name: non-root-pod
		spec:
			containers:
			- image: nginx:alpine
			name: non-root-pod
			securityContext:        
				runAsNonRoot: false
			resources: {}
			dnsPolicy: ClusterFirst
			restartPolicy: Always

	</details>

	Apply generated yaml file:
	```
	k apply -f non-root-pod.yaml
	```
	

</details>

- <details><summary>Example_4: Run container as user:</summary>
	
	```
	k run run-as-user-pod --image=nginx:alpine --dry-run=client -o yaml > run-as-user-pod.yaml
	```

	<details><summary> Edit that run-as-user-pod.yaml file to:</summary>
	
		---
		apiVersion: v1
		kind: Pod
		metadata:
			labels:
				run: run-as-user-pod
			name: run-as-user-pod
		spec:
			securityContext:
				runAsUser: 1001
				runAsGroup: 1001
			containers:
			- image: nginx:alpine
			  name: run-as-user-pod
			  resources: {}
			  securityContext:
				allowPrivilegeEscalation: false
			dnsPolicy: ClusterFirst
			restartPolicy: Always

	</details>

	Apply the YAML:
	```
	k apply -f run-as-user-pod.yaml
	```
	

</details>

**Useful official documentation**

- [runAsUser/runAsGroup](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Privilege Escalation](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Privileged containers](https://kubernetes.io/docs/concepts/workloads/pods/)

**Useful non-official documentation**

- None


## Minimize Microservice Vulnerabilities - 20%

### 1. Setup appropriate OS-level security domains

OS-level security domains can be used to isolate microservices from each other and from the host OS. This can help to prevent microservices from interfering with each other and from being exploited by attackers.

Examples:
- <details><summary>Example_1: Working with Open Policy Agent (OPA)/Gatekeeper:</summary>

	To install:
	```
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
	```

	Deploy some example (k8srequiredlabels):
	```
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/demo/basic/templates/k8srequiredlabels_template.yaml
	```

	You can install this Constraint with the following command:
	```
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/demo/basic/constraints/all_ns_must_have_gatekeeper.yaml
	```

	To check constraints:
	```
	kubectl get constraints
	```

</details>

- <details><summary>Example_2: Working with Security context:</summary>

	It's already described on other topics with a lot of examples.

</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [Opa gatekeeper policy and governance for kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
- [Openpolicyagent](https://www.openpolicyagent.org/docs/latest/kubernetes-primer/)
- [Openpolicyagent online editor](https://play.openpolicyagent.org/)
- [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/)
- [Security context for pods](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes security psp network policy](https://sysdig.com/blog/kubernetes-security-psp-network-policy/)

### 2. Manage Kubernetes secrets

Kubernetes secrets can be used to store sensitive information such as passwords and API keys. It is important to manage secrets securely by encrypting them and by restricting access to them.

Examples:
- <details><summary>Example_1: Secret Access in Pods:</summary>

	Create a secret with `literal-secret` name through CLI:
	```
	kubectl create secret generic literal-secret --from-literal secret=secret12345
	```

	Create a new secret with `file-secret` name through `file-secret.yaml` file:
	```
	---
	apiVersion: v1
	kind: Secret
	metadata:
	  name: file-secret
	data:
	  hosts: MTI3LjAuMC4xCWxvY2FsaG9zdAoxMjcuMC4xLjEJaG9zdDAxCgojIFRoZSBmb2xsb3dpbmcgbGluZXMgYXJlIGRlc2lyYWJsZSBmb3IgSVB2NiBjYXBhYmxlIGhvc3RzCjo6MSAgICAgbG9jYWxob3N0IGlwNi1sb2NhbGhvc3QgaXA2LWxvb3BiYWNrCmZmMDI6OjEgaXA2LWFsbG5vZGVzCmZmMDI6OjIgaXA2LWFsbHJvdXRlcnMKMTI3LjAuMC4xIGhvc3QwMQoxMjcuMC4wLjEgaG9zdDAxCjEyNy4wLjAuMSBob3N0MDEKMTI3LjAuMC4xIGNvbnRyb2xwbGFuZQoxNzIuMTcuMC4zNSBub2RlMDEKMTcyLjE3LjAuMjMgY29udHJvbHBsYW5lCg==
	```

	Apply it:
	```
	k apply -f file-secret.yaml
	```

	Then, create a new pod with `pod-secrets` name. Make Secret `literal-secret` available as environment variable `literal-secret`. Mount Secret `file-secret` as volume. The file should be available under `/etc/file-secret/hosts`:
	```
	---
	apiVersion: v1
	kind: Pod
	metadata:
	name: pod-secrets
	spec:
	volumes:
	- name: file-secret
		secret:
		secretName: file-secret
	containers:
	- image: nginx
		name: pod-secrets
		volumeMounts:
		- name: file-secret
			mountPath: /etc/file-secret
		env:
		- name: literal-secret
			valueFrom:
			secretKeyRef:
				name: literal-secret
				key: secret
	```

	Verify:
	```
	kubectl exec pod-secrets -- env | grep "secret=secret12345"
	
	kubectl exec pod-secrets -- cat /etc/file-secret/hosts
	```

</details>

- <details><summary>Example_2: Secret Read and Decode:</summary>

	Get the secret that created in `opaque` ns and store it into `opaque_secret.txt` file:
	```
	kubectl -n opaque get secret test-sec-1 -ojsonpath="{.data.data}" | base64 -d > opaque_secret.txt
	```

</details>

- <details><summary>Example_3: Secret etcd encryption. Use aesgcm encryption for etcd:</summary>

	Creating folder for this task:
	```
	mkdir -p /etc/kubernetes/enc
	```

	Encrypt secret phrase, for example:
	```
	echo -n Secret-ETCD-Encryption | base64
		U2VjcmV0LUVUQ0QtRW5jcnlwdGlvbg==
	```

	Create EncryptionConfiguration `/etc/kubernetes/enc/encryption.yaml` file:
	```
	---
	apiVersion: apiserver.config.k8s.io/v1
	kind: EncryptionConfiguration
	resources:
	- resources:
		- secrets
		providers:
		- aesgcm:
			keys:
			- name: key1
			  secret: U2VjcmV0LUVUQ0QtRW5jcnlwdGlvbg==
		- identity: {}
	```

	Open `/etc/kubernetes/manifests/kube-apiserver.yaml` file and put `encryption-provider-config` parameter. Also add volume and volumeMount, for example:
	```
	spec:
		containers:
		- command:
			- kube-apiserver
		...
			- --encryption-provider-config=/etc/kubernetes/enc/encryption.yaml
		...
			volumeMounts:
			- mountPath: /etc/kubernetes/enc
			name: enc
			readOnly: true
		...
		hostNetwork: true
		priorityClassName: system-cluster-critical
		volumes:
		- hostPath:
			path: /etc/kubernetes/enc
			type: DirectoryOrCreate
			name: enc
		...
	```
	Wait till apiserver was restarted:
	```
	watch crictl ps
	```

	When `apiserver` will be re-created, we can encrypt all existing secrets. For example, let's do it fort all secrets in `one1` NS:
	```
	kubectl -n one1 get secrets -o json | kubectl replace -f -
	```

	To check you can do for example:
	```
	ETCDCTL_API=3 etcdctl \
	--cert /etc/kubernetes/pki/apiserver-etcd-client.crt \
	--key /etc/kubernetes/pki/apiserver-etcd-client.key \
	--cacert /etc/kubernetes/pki/etcd/ca.crt \
	get /registry/secrets/one1/s1
	```

</details>

**Useful official documentation**

- [Distribute credentials secure](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)
- [Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Encrypt data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kube apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [ETCd encryption](https://etcd.io/docs/v3.5/op-guide/configuration/#security)

**Useful non-official documentation**

- None

### 3. Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)

Before the open container initiative (OCI) proposed to have Container Runtime Interface(CRI), the communication between containers and Kubernetes (K8s) was relying on dockershim/rkt provided and maintained by Docker. However, when containers and K8s are getting more and more sophisticated, the maintenance cost of dockershim/rkt becomes higher and higher. Therefore, having an interface that opens to the open source community and for solely dealing with container runtime becomes the answer to this challenging situation.

Kata Containers and gVisor helps in workload isolation. It can be implemented using the Kubernetes RuntimeClass where you can specify the required runtime for the workload.

Examples:
 - <details><summary>Example_1: Use ReadOnly Root FileSystem. Create a new Pod named my-ro-pod in Namespace application of image busybox:1.32.0. Make sure the container keeps running, like using sleep 1d. The container root filesystem should be read-only:</summary>
	
	Create RuntimeClass class, something like. Put the next data to `rtc.yaml` file:
	```
	---
	apiVersion: node.k8s.io/v1
	kind: RuntimeClass
	metadata:
	  name: gvisor
	handler: runsc
	```

	Then, apply the file: 
	```
	k apply -f rtc.yaml
	```

	Deploy a new pod with created RuntimeClass, an example `sec_pod.yaml`:
	```
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
	```

	Then, apply the file: 
	```
	k apply -f sec_pod.yaml
	```

	Checks:
	```
	k exec sec -- dmesg
	```

</details>

**Useful official documentation**

- [Runtime class](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [Encrypt data](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

**Useful non-official documentation**

- [Gvisor](https://gvisor.dev/docs/user_guide/install/)
- [Runtime class examples](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/585-runtime-class/README.md#examples)

### 4. Implement pod-to-pod encryption by use of mTLS

mTLS stands for mutual authentication, meaning client authenticates server and server does the same to client, its core concept is to secure pod-to-pod communications. In exams it may ask you to create the certificates. However, it is worth bookmarking certificate signing requests and understanding how to implement kubeconfig access and mTLS authentication credentials.

What nTLS is?
Mutual TLS takes TLS to the next level by authenticating both sides of the client-server connection before exchanging communications. This may seem like a common-sense approach, but there are many situations where the client’s identity is irrelevant to the connection.

When only the server’s identity matters, standard unidirectional TLS is the most efficient approach. TLS uses public-key encryption, requiring a private and public key pair for encrypted communications. To verify the server’s identity, the client sends a message encrypted using the public key (obtained from the server’s TLS certificate) to the server. Only a server holding the appropriate private key can decrypt the message, so successful decryption authenticates the server. 

To have bi-directional authentication would require that all clients also have TLS certificates, which come from a certificate authority. Because of the sheer number of potential clients (browsers accessing websites, for example), generating and managing so many certificates would be extremely difficult.

However, for some applications and services, it can be crucial to verify that only trusted clients connect to the server. Perhaps only certain users should have access to particular servers. Or maybe you have API calls that should only come from specific services. In these situations, the added burdens of mTLS are well worth it. And if your organization reinforces security with zero trust policies where every attempt to access the server must be verified, mTLS is necessary.

mTLS adds a separate authentication of the client following verification of the server. Only after verifying both parties to the connection can the two exchange data. With mTLS, the server knows that a trusted source is attempting to access it.

Examples:
- <details><summary>Example_1: Using mTLS:</summary>

	No need it for examination. For general development, read the material.

</details>

**Useful official documentation**

- [mTLS](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)

**Useful non-official documentation**

- [Why we need mTLS](https://trstringer.com/why-we-need-mtls/)
- [Kubernetes mTLS](https://tanzu.vmware.com/developer/guides/kubernetes-mtls/)
- [mTLS](https://www.istioworkshop.io/11-security/01-mtls/)
- [Istio](https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/)
- [Istio auto mutual TLS](https://istio.io/latest/docs/tasks/security/authentication/authn-policy/#auto-mutual-tls)
- [What is mTLS and How to implement it with Istio](https://imesh.ai/blog/what-is-mtls-and-how-to-implement-it-with-istio/)
- [Linkerd](https://linkerd.io/2/features/automatic-mtls/)


## Supply Chain Security - 20% 

### 1. Minimize base image footprint

Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
Do not include uncessary software not required for container during runtime e.g build tools and utilities, troubleshooting and debug binaries.
The smaller the base image footprint, the less vulnerable your containers are. Use minimal base images and avoid adding unnecessary packages or services to your base images.

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

	Edit deploy and put needed sha:
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

	There is a Dockerfile at `/root/Dockerfile`. It’s a simple container which tries to make a curl call to an imaginary api with a secret token, the call will 404, but that's okay:
	- Use specific version 20.04 for the base image
	- Remove layer caching issues with apt-get
	- Remove the hardcoded secret value 2e064aad-3a90–4cde-ad86–16fad1f8943e. The secret value should be passed into the container during runtime as env variable TOKEN
	- Make it impossible to docker exec , podman exec or kubectl exec into the container using bash

	Dockerfile (before):
	```
	FROM ubuntu
	RUN apt-get update
	RUN apt-get -y install curl
	ENV URL https://google.com/this-will-fail?secret-token=
	CMD ["sh", "-c", "curl --head $URL=2e064aad-3a90-4cde-ad86-16fad1f8943e"]
	```

	Dockerfile (after):
	```
	FROM ubuntu:20.04
	RUN apt-get update && apt-get -y install curl
	ENV URL https://google.com/this-will-fail?secret-token=
	RUN rm /usr/bin/bash
	CMD ["sh", "-c", "curl --head $URL$TOKEN"]
	```

	Testing:
	```
	podman build -t app .
	podman run -d -e TOKEN=6666666-5555555-444444-33333-22222-11111 app sleep 1d
	podman ps | grep app
	podman exec -it 4a848daec2e2 bash # fails
	podman exec -it 4a848daec2e2 sh # works
	```

	NOTE: you can use `docker` or `podman` to work with Dockerfile and containers.

</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [7 best practices for building containers](https://cloud.google.com/blog/products/containers-kubernetes/7-best-practices-for-building-containers)
- [Smaller Docker images](https://learnk8s.io/blog/smaller-docker-images)
- [Kubernetes best practices how and why to build small container images](https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-how-and-why-to-build-small-container-images)
- [Best practices for building containers](https://cloud.google.com/architecture/best-practices-for-building-containers#build-the-smallest-image-possible)
- [Multi stages for Docker](https://docs.docker.com/build/building/multi-stage/)
- [Tips to reduce Docker image sizes](https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34)
- [Docker Image Security Best Practices](https://res.cloudinary.com/snyk/image/upload/v1551798390/Docker_Image_Security_Best_Practices_.pdf)
- [3 simple tricks for smaller Docker images](https://learnk8s.io/blog/smaller-docker-images)
- [Top 20 Dockerfile best practices](https://sysdig.com/blog/dockerfile-best-practices/)
- [Checkov](https://www.checkov.io/)

### 2. Secure your supply chain: whitelist allowed registries, sign and validate images

Securing the images that are allowed to run in your cluster is essential. It’s important to verify the pulled base images are from valid sources. This can be done by ImagePolicyWebhook admission controller.

Examples:
 - <details><summary>Example_1: Use ImagePolicyWebhook:</summary>

	<details><summary>First of all, let's create admission /etc/kubernetes/policywebhook/admission_config.json config</summary>
	
		{
			"apiVersion": "apiserver.config.k8s.io/v1",
			"kind": "AdmissionConfiguration",
			"plugins": [
				{
					"name": "ImagePolicyWebhook",
					"configuration": {
						"imagePolicy": {
						"kubeConfigFile": "/etc/kubernetes/policywebhook/kubeconf",
						"allowTTL": 150,
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

		---
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

	Checks:
	```
	crictl ps -a | grep api
	crictl logs 91c61357ef147
	
	k run pod --image=nginx
	
	Error from server (Forbidden): pods "pod" is forbidden: Post "https://localhost:1234/?timeout=30s": dial tcp 127.0.0.1:1234: connect: connection refused
	```

</details>

**Useful official documentation**

- [Admission controllers (imagepolicywebhook)](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
- [Extensible admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

**Useful non-official documentation**

- [Why do I need admission controllers](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers)

### 3. Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)

This is totally straightforward. You will need to vet the configuration of Kubernetes YAML files and Docker files and fix any security issues.

Examples:
- <details><summary>Example_1: Static Manual Analysis Docker:</summary>

	Everyone must understand Dockerfile and fix it with best practices (without any tools).
	

</details>

- <details><summary>Example_2: Static Manual analysis k8s:</summary>

	Everyone must understand YAML files of deployments/pods/etc and fix them out with best practices (without any tools).
	

</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [7 statically analyse yaml](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml)
- [Kubehunter](https://github.com/aquasecurity/kube-hunter)
- [Kubesec](https://kubesec.io/)
- [Checkov](https://bridgecrew.io/blog/kubernetes-static-code-analysis-with-checkov/)
- [Clair](https://github.com/quay/clair)
- [Kube-score](https://kube-score.com/)
- [Conftest](https://www.conftest.dev/)
	
### 4. Scan images for known vulnerabilities 

- <details><summary>Example_1: Using trivy to scan images in applications and infra namespaces and define if the images has CVE-2021-28831 and/or CVE-2016-9841 vulnerabilities. Scale down those Deployments to 0 if you will find something:</summary>

	Getting images:
	```
	k -n applications get pod -oyaml | grep image: | sort -rn | uniq
	- image: nginx:1.20.2-alpine
	- image: nginx:1.19.1-alpine-perl
	image: docker.io/library/nginx:1.20.2-alpine
	image: docker.io/library/nginx:1.19.1-alpine-perl
	```

	Let's scan first deployment:
	```
	trivy image nginx:1.19.1-alpine-perl | grep CVE-2021-28831
	trivy image nginx:1.19.1-alpine-perl | grep CVE-2016-9841
	```

	Let's scan second deployment:
	```
	trivy image nginx:1.20.2-alpine | grep CVE-2021-28831
	trivy image nginx:1.20.2-alpine | grep CVE-2016-9841
	```

	Hit on the first one, so we scale down:
	```
	k -n applications scale deploy web1 --replicas 0
	```
	

</details>

- <details><summary>Example_2: Using trivy to scan images in default namespace:</summary>

	Getting images from all pods in `default` NS:
	```
	k get po -o yaml | grep image: | sort -rn | uniq
	```

	Let's scan second `nginx:1.19.2`:
	```
	trivy --severity HIGH,CRITICAL nginx:1.19.2
	```

</details>

**Useful official documentation**

- None

**Useful non-official documentation**

- [Scan images and run ids](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids)
- [Anchore](https://github.com/anchore/anchore-cli#command-line-examples)
- [Trivy](https://github.com/aquasecurity/trivy)


## Monitoring, Logging, and Runtime Security - 20%

### 1. Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities

Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities.

Examples:
 - <details><summary>Example_1: Use seccomp:</summary>
	
	There is a JSON format for writing custom seccomp profiles: A fundamental seccomp profile has three main elements: defaultAction, architectures and syscalls:
	```
	{
		"defaultAction": "",
		"architectures": [],
		"syscalls": [
			{
				"names": [],
				"action": ""
			}
		]
	}
	```

	Using the following pattern we can whitelist only those system calls we want to allow from a process:
	```
	{
		"defaultAction": "SCMP_ACT_ERRNO",
		"architectures": [
			"SCMP_ARCH_X86_64",
			"SCMP_ARCH_X86",
			"SCMP_ARCH_X32"
		],
		"syscalls": [
			{
				"names": [
					"pselect6",
					"getsockname",
					..
					..
					"execve",
					"exit"
				],
				"action": "SCMP_ACT_ALLOW"
			}
		]
	}
	```

	In contrast, if we write a seccomp profile similar to the following pattern that will help us to blacklist the system calls we want to restrict and all other calls will be allowed:
	```
	{
		"defaultAction": "SCMP_ACT_ALLOW",
		"architectures": [
			"SCMP_ARCH_X86_64",
			"SCMP_ARCH_X86",
			"SCMP_ARCH_X32"
		],
		"syscalls": [
			{
				"names": [
					"pselect6",
					"getsockname",
					..
					.. 
					..
					"execve",
					"exit"
				],
				"action": "SCMP_ACT_ERRNO" 
			}
		]
	}
	```

	The default root directory of the kubelet is : `/var/lib/kubelet`. Now create new directory under kubelet root directory:
	```
	mkdir -p /var/lib/kubelet/seccomp/profiles
	```

	Store the config file inside that dir:
	```
	vim /var/lib/kubelet/seccomp/profiles/auditing.json
	```

	Inside your deployment or pod, adding config:
	```
	----
	apiVersion: v1
	kind: Pod
	metadata:
	name: local-seccomp-profile
	spec:
	securityContext:
		seccompProfile:
		# Profile from local node
		type: Localhost
		localhostProfile: profiles/auditing.json
	containers:
	- name: container
		image: nginx
	
	----
	apiVersion: v1
	kind: Pod
	metadata:
	name: runtime-default-profile
	spec:
	securityContext:
		# Container runtime default profile
		seccompProfile:
		type: RunTimeDefault
	containers:
	- name: test-container
		image: nginx
	```

</details>

- <details><summary>Example_2: Use strace:</summary>

	For, example:
	```
	strace -c -f -S name chmod 2>&1 1>/dev/null | tail -n +3 | head -n -2 | awk '{print $(NF)}'
	```

</details>

- <details><summary>Example_3: Use sysdig:</summary>

	If you would like to use Sysdig:
	```
	sysdig proc.name=ls
	```

</details>

**Useful official documentation**

- [Seccomp]( https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Falco](https://falco.org/docs/)
- [Sysdig docs](https://docs.sysdig.com/en/)
- [Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

**Useful non-official documentation**

- [How to detect Kubernetes vulnerability with falco](https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/)
- [Falco 101](https://learn.sysdig.com/falco-101)
- [Helm-chart to deploy Falco](https://github.com/falcosecurity/charts/tree/master/falco)
- [Detect CVE-2020 and CVE-8557](https://falco.org/blog/detect-cve-2020-8557/)
- [Sysdig User Guide](https://github.com/draios/sysdig/wiki/Sysdig%20User%20Guide#filtering)
- [Secure Computing with Seccomp](https://levelup.gitconnected.com/seccomp-secure-computing-mode-kubernetes-docker-97130516662c)
- [Kubernetes Security Tools: Seccomp & AppArmor](https://medium.com/@noah_h/kubernetes-security-tools-seccomp-apparmor-586fdc61e6d9)

### 2. Detect threats within a physical infrastructure, apps, networks, data, users, and workloads

Examples:
- <details><summary>Example_1 Detect shell exec in all containers with Falco</summary>
	
	Create a new rule to detect shell inside container only for `nginx` PODs with the next format `Shell in container: TIMESTAMP,USER,COMMAND/SHELL` line. Set the priority to `CRITICAL`. Enable file output into `/var/log/falco.txt` file.

	First of all, let's start from file output, so - open `/etc/falco/falco.yaml` file, find the lines and put something like:
	```
	file_output:
	enabled: true
	keep_alive: false
	filename: /var/log/falco.txt
	```

	Now, lets configure custom output commands for "Terminal shell in container" rule. So, open `/etc/falco/falco_rules.local.yaml` file and put the next:
	```
	---
  
  	# macros
	- macro: container
	  condition: (container.id != host)
	
	- macro: spawned_process
	  condition: evt.type in (execve, execveat) and evt.dir=<
	
	- macro: shell_procs
	  condition: proc.name in (shell_binaries)
	
	- macro: container_entrypoint
	  condition: (not proc.pname exists or proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc, docker-runc, exe, docker-runc-cur))
	
	- macro: never_true
	  condition: (evt.num=0)
	
	- macro: user_expected_terminal_shell_in_container_conditions
	  condition: (never_true)
	
	# rules
	- rule: Terminal shell in container 1
	  desc: detect spawned process by user name
	  condition: >
	    spawned_process 
	    and container
	    and container.name = "nginx"
	    and shell_procs and proc.tty != 0
	    and container_entrypoint
	    and not user_expected_terminal_shell_in_container_conditions
	  output: >
	    Shell in container: %evt.time,%user.name,%proc.cmdline
	  priority: CRITICAL
	  tags: [container, shell]
	
	- rule: Terminal shell in container 2
	  desc: detect spawned process by user ID
	  condition: >
	    spawned_process
	    and container
	    and container.name = "nginx"
	    and shell_procs and proc.tty != 0
	    and container_entrypoint
	    and not user_expected_terminal_shell_in_container_conditions
	  output: >
	    Shell in container: %evt.time,%user.uid,%proc.cmdline
	  priority: CRITICAL
	  tags: [container, shell]
	```
	
	NOTE: if you want to get syscalls for your output (text format), you can use the enxt command: `falco --list=syscall`.
	
	Restart Falco service:
	```
	service falco restart && service falco status
	```
	
	Checks:
	```
	k run nginx --image=nginx:alpine
	
	k exec -it nginx -- sh
	
	cat /var/log/syslog | grep falco | grep -Ei "Shell in container"
	```

</details>

- <details><summary>Example_2 Detect shell exec in one specific container with Falco</summary>
	
	Create a new rule to detect shell inside container only for `nginx` PODs with the next format `Shell in container: TIMESTAMP,USER,COMMAND/SHELL` line. Set the priority to `CRITICAL`. Enable file output into `/var/log/falco.txt` file.

	First of all, let's start from file output, so - open `/etc/falco/falco.yaml` file, find the lines and put something like:
	```
	file_output:
	enabled: true
	keep_alive: false
	filename: /var/log/falco.txt
	```

	Now, lets configure custom output commands for "Terminal shell in container" rule. So, open `/etc/falco/falco_rules.local.yaml` file and put the next:
	```
	- macro: app_nginx
  	  condition: container and container.image contains "nginx"
	
	- list: nginx_allowed_processes
      items: ["nginx", "app-entrypoint.", "basename", "dirname", "grep", "nami", "node", "tini"]
	
	- rule: Terminal shell in container
	  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
	  condition: >
		spawned_process and app_nginx
		and not proc.name in (nginx_allowed_processes)
		and shell_procs and proc.tty != 0
		and container_entrypoint
		and not user_expected_terminal_shell_in_container_conditions
	  output: >
		Shell in container: %evt.time,%user.name,%proc.cmdline
	  priority: CRITICAL
	  tags: [container, shell, mitre_execution, app_nginx]
	```

	NOTE: if you want to get syscalls for your output (text format), you can use the enxt command: `falco --list=syscall`.

	Restart Falco service:
	```
	service falco restart && service falco status
	```

	Checks:
	```
	k run nginx --image=nginx:alpine
	
	k exec -it nginx -- sh
	
	cat /var/log/syslog | grep falco | grep -Ei "Shell in container"
	```

</details>

- <details><summary>Example_3 detect anomalous processes that occur and execute frequently in a single container with Sysdig</summary>
	
	Use sysdig tool to detect anomalous processes that occur and execute frequently in a single container of Pod `myredis`.

	NOTE: These tools are pre-installed on the cluster's worker node `node01` only, not on the master node.


	Use the tools to analyze the spawned and executed processes for at least `60` seconds, checking them with filters and writing the events to the file `/opt/incidents/summary`, which contains the detected events in the following format. This file contains the detected events in the following format: `timestamp,uid/username,processName`. Keep the original timestamp format of the tool intact.
	NOTE: Ensure that the events file is stored on a working node in the cluster.
	
	The output example of formatted events should be like:
	```
	01:33:19.601363716,root,init
	01:33:20.606013716,nobody,bash
	01:33:21.137163716,1000,tar
	```
	
	Use for all pods:
	```
	sysdig -M 10 -p "%evt.time,%user.uid,%proc.name"
	```
	
	Use for specific container ID (`myredis`):
	```
	sysdig -M 60 -p "%evt.time,%user.name,%proc.name" container.name=myredis >> /opt/incidents/summary
	
	Or:
	sysdig -M 60 -p "%evt.time,%user.name,%proc.name" container.id=$(kubectl get po myredis -o json | jq -r '.status.containerStatuses[].containerID'| tr -d 'containerd://') >> /opt/incidents/user.name/summary
	```
	
	Use for specific container name - `myredis`:
	```
	sysdig -M 60 -p "%evt.time,%user.uid,%proc.name" container.name=myredis >> /opt/incidents/summary
	```
	
	Or:
	```
	sysdig -pc "container.name=myredis and evt.type in (execve, execveat) and evt.dir=<" -p '%evt.time,%user.uid,%proc.name' >> /opt/incidents/summary
	```
	
	*NOTE*: To get list of events, you can use:
	```
	sysdig --list
	
	sysdig --list | grep time
	```
	
	For testing, create container:
	```
	k run myredis --image=redis
	k exec -ti myredis -- sh
	```
	
	Then, run some command(s) inside the container to get output.

</details>

- <details><summary>Example_4 detect spawned processes in container(s) with Falco</summary>
	The sriteria is to detect spawned processes in container only for `nginx` PODs with the next format `Spawned process in container: TIMESTAMP,USER,COMMAND/SHELL` line. Set the priority to `CRITICAL`. Enable file output into `/var/log/falco.txt` file.

	First of all, let's start from file output, so - open `/etc/falco/falco.yaml` file, find the lines and put something like:
	```
	file_output:
	enabled: true
	keep_alive: false
	filename: /var/log/falco.txt
	```

	Now, open `/etc/falco/falco_rules.local.yaml` file and put the next rule:
	```
	- rule: spawned_process_in_container
	desc: A process was spawned in the container.
	condition: >
	   evt.type = execve and container.name = "nginx"
	output: >
	   Spawned process in container: %evt.time,%user.name,%proc.cmdline
	priority: CRITICAL
	```

	Or, cna re-use macros:
	```
	- rule: spawned_process_in_container
	desc: A process was spawned in the container.
	condition: >
	   spawned_process and container.name = "nginx"
	output: >
	   Spawned process in container: %evt.time,%user.name,%proc.cmdline
	priority: CRITICAL
	```
	
	NOTE: if you want to get syscalls for your output (text format), you can use the enxt command: `falco --list=syscall`.

	Restart Falco service:
	```
	service falco restart && service falco status
	```

	Checks:
	```
	k run nginx --image=nginx:alpine
	
	k exec -it nginx -- sh
	
	cat /var/log/syslog | grep falco | grep -Ei "Shell in container"
	```

	Or, you can run the below command for running falco every 30 seconds and store data in file:
	```
	falco -M 30 -r /etc/falco/falco_rules.local.yaml > /var/log/falco.txt
	```

</details>

**Useful official documentation**

- [Falco docs](https://falco.org/docs)
- [Sysdig docs](https://docs.sysdig.com/en/)

**Useful non-official documentation**

- [Common Kubernetes config security threats](https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/)
- [Guidance on Kubernetes threat modeling](https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/guidance-on-kubernetes-threat-modeling)
- [Attack matrix Kubernetes](https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/)
- [Sysdig Examples](https://github.com/draios/sysdig/wiki/Sysdig-Examples#security)
- [Monitoring Command Execution In Containers With Sysdig](https://keefer.io/posts/sysdig-monitoring/)
- [Falco security](https://artifacthub.io/packages/helm/falcosecurity/falco)
- [Kubernetes Security Tools: Falco](https://medium.com/@noah_h/kubernetes-security-tools-falco-e873831f3d3d)

### 3. Detect all phases of attack regardless of where it occurs and how it spreads

This part of the task can be done with OPA for example and allow pulling images from private container image registries only.

**Useful official documentation**

- [Falco](https://falco.org/)
- [Sysdig docs](https://docs.sysdig.com/en/)

**Useful non-official documentation**

- [Attack matrix Kubernetes](https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/)
- [Mitre attck framework for container runtime security with sysdig falco](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
- [Mitigating Kubernetes attacks](https://www.cncf.io/online-programs/mitigating-kubernetes-attacks/)
- [Anatomy Kubernetes attack how untrusted docker images fail us](https://www.optiv.com/insights/source-zero/blog/anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us)
- [Webinar: Mitigating Kubernetes attacks](https://www.youtube.com/watch?v=HWv8ZKLCawM&ab_channel=CNCF%5BCloudNativeComputingFoundation%5D)

### 4. Perform deep analytical investigation and identification of bad actors within the environment

Probably Falco can help to take care of it. You can easily put some Falco's rules to detect who and which UID enter inside container.

**Useful official documentation**

- [Sysdig](https://docs.sysdig.com/en/)
- [Falco](https://falco.org/)

**Useful non-official documentation**

- [Monitoring Kubernetes with Sysdig](https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/)
- [CNCF Webinar: Getting started with container runtime security using Falco](https://www.youtube.com/watch?v=VEFaGjfjfyc&ab_channel=Sysdig)
- [Kubernetes security](https://www.redhat.com/en/topics/containers/kubernetes-security)

### 5. Ensure immutability of containers at runtime

Immutability of Volumes (Secrets, ConfigMaps, VolumeMounts) can be achieved with `readOnly`: true field on the mount.
```
volumeMounts:
- name: instance-creds
  mountPath: /secrets/creds
  readOnly: true
```

**Useful official documentation**

- [Kubernetes volumes](https://kubernetes.io/docs/concepts/storage/volumes/)

**Useful non-official documentation**

- [Principles of container app design](https://kubernetes.io/blog/2018/03/principles-of-container-app-design/)
- [Why I think we should all use immutable docker images](https://medium.com/sroze/why-i-think-we-should-all-use-immutable-docker-images-9f4fdcb5212f)
- [Immutable infrastructure your systems can rise dead](https://techbeacon.com/enterprise-it/immutable-infrastructure-your-systems-can-rise-dead)

### 6. Use Audit Logs to monitor access

The kube-apiserver allows us to capture the logs at various stages of a request sent to it. This includes the events at the metadata stage, request, and response bodies as well. Kubernetes allows us to define the stages which we intend to capture. The following are the allowed stages in the Kubernetes audit logging framework:
- RequestReceived: As the name suggests, this stage captures the generated events as soon as the audit handler receives the request.
- ResponseStarted: In this stage, collects the events once the response headers are sent, but just before the response body is sent.
- ResponseComplete: This stage collects the events after the response body is sent completely.
- Panic: Events collected whenever the apiserever panics.

The level field in the rules list defines what properties of an event are recorded. An important aspect of audit logging in Kubernetes is, whenever an event is processed it is matched against the rules defined in the config file in order. The first rule sets the audit level of logging the event. Kubernetes provides the following audit levels while defining the audit configuration:
- Metadata: Logs request metadata (requesting user/userGroup, timestamp, resource/subresource, verb, status, etc.) but not request or response bodies.
- Request: This level records the event metadata and request body but does not log the response body.
- RequestResponse: It is more verbose among all the levels as this level logs the Metadata, request, and response bodies.
- None: This disables logging of any event that matches the rule.

Examples:

- <details><summary>Example_1: Create Audit policy for Kubernetes cluster.</summary>

	Let's create policy, where you must log logs of PODs inside `prod` NS when you created them. Other requests should not be logged at all.

	Create `/etc/kubernetes/auditing/policy.yaml` policy file with the next configuration:
	```
	---
	apiVersion: audit.k8s.io/v1 # This is required.
	kind: Policy
	# Don't generate audit events for all requests in RequestReceived stage.
	omitStages:
	- "RequestReceived"
	rules:
	- level: Metadata
		namespaces: ["prod"]
		verbs: ["create"]
		resources:
		- group: "" # core
		  resources: ["pods"]
	
	# Log all other resources in core and extensions at the Request level.
	- level: Request
		resources:
		- group: "" # core API group
		- group: "extensions" # Version of group should NOT be included.
	
	# Log pod changes at RequestResponse level
	- level: RequestResponse
		resources:
		- group: ""
		resources: ["pods"]
	
	# Don't log any other requests"
	- level: None
	```

	Next, edit kube-api configuration:
	```	
	vim /etc/kubernetes/manifests/kube-apiserver.yaml
	```

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

	Checks:
	```
	crictl ps -a | grep api
	
	tail -fn10 /etc/kubernetes/audit-logs/audit.log
	```

</details>

- <details><summary>Example_2: Configure the Apiserver for Audit Logging. The log path should be /etc/kubernetes/audit-logs/audit.log on the host and inside the container. The existing Audit Policy to use is at /etc/kubernetes/auditing/policy.yaml. The path should be the same on the host and inside the container. Also, set argument --audit-log-maxsize=3 and set argument --audit-log-maxbackup=4:</summary>
	
	Edit kube-api configuration:
	```	
	vim /etc/kubernetes/manifests/kube-apiserver.yaml
	```

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

	Checks:
	```
	crictl ps -a | grep api
	tail -f /etc/kubernetes/audit-logs/audit.log
	```
	

</details>

**Useful official documentation**

- [Kubernetes cluster audit](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

**Useful non-official documentation**

- [Kubernetes audit logging](https://docs.sysdig.com/en/docs/sysdig-secure/secure-events/kubernetes-audit-logging/)
- [Monitor Kubernetes audit logs](https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/)

### 7. ReadOnly Root FileSystem

Examples:
 - <details><summary>Example_1: Use ReadOnly Root FileSystem. Create a new Pod named my-ro-pod in Namespace application of image busybox:1.32.0. Make sure the container keeps running, like using sleep 1d. The container root filesystem should be read-only:</summary>
	
	Generate configuration:
	```
	k -n application run my-ro-pod --image=busybox:1.32.0 -oyaml --dry-run=client --command -- sh -c 'sleep 1d' > my-ro-pod.yaml
	```

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

- [Kubernetwe security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

**Useful non-official documentation**

- None


# Additional useful material

## Articles

1. [Cheatsheet for Kubernetes](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

## Books

1. [Container Security](https://devopscube.com/recommends/container-security/)
2. [Kubernetes Security](https://devopscube.com/recommends/kubernetes-security/)
3. [Learn Kubernetes security: Securely orchestrate, scale, and manage your microservices in Kubernetes deployments](https://www.amazon.com/Learn-Kubernetes-Security-orchestrate-microservices/dp/1839216506)
4. [Downloaded books inside this project](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/tree/main/hands-on/books)

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
8. [k8simulator](https://k8simulator.com/product/certified-kubernetes-security-specialist-cks/)


# Authors

Created and maintained by [Vitalii Natarov](https://github.com/SebastianUA). An email: [vitaliy.natarov@yahoo.com](vitaliy.natarov@yahoo.com).


# License
Apache 2 Licensed. See [LICENSE](https://github.com/SebastianUA/Certified-Kubernetes-Security-Specialist/blob/main/LICENSE) for full details.