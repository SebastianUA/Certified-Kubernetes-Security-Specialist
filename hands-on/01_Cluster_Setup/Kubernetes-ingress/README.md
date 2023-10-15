# Ingress-Nginx Controller for Kubernetes

Sample deployment of [Ingress-Nginx Controller](https://kubernetes.github.io/ingress-nginx/) for Kubernetes with security best practices.


## Ingress-Nginx Controller

### Verify you are running with a compatible version of the tools

kubectl:
```
$ kubectl version --output json
{
    "clientVersion": {
        "major": "1",
        "minor": "28",
        "gitVersion": "v1.28.2",
        "gitCommit": "89a4ea3e1e4ddd7f7572286090359983e0387b2f",
        "gitTreeState": "clean",
        "buildDate": "2023-09-13T09:35:49Z",
        "goVersion": "go1.20.8",
        "compiler": "gc",
        "platform": "darwin/arm64"
    },
    "kustomizeVersion": "v5.0.4-0.20230601165947-6ce0bf390ce3",
    "serverVersion": {
        "major": "1",
        "minor": "27",
        "gitVersion": "v1.27.2",
        "gitCommit": "7f6f68fdabc4df88cfea2dcf9a19b2b830f1e647",
        "gitTreeState": "clean",
        "buildDate": "2023-05-17T14:13:28Z",
        "goVersion": "go1.20.4",
        "compiler": "gc",
        "platform": "linux/arm64"
    }
}
```

Helm:
```
$ helm version --short
v3.12.3+g3a31588
```

### Install Nginx Ingress Controller


Adding repo:
```
$ helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
"ingress-nginx" has been added to your repositories
```

Getting updates:
```
$ helm repo update ingress-nginx
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "ingress-nginx" chart repository
Update Complete. ⎈Happy Helming!⎈
```

Installing:
```
$ helm upgrade --install ingress-nginx \
    --namespace ingress-nginx \
    --create-namespace \
    --values values.yaml \
    --wait \
    ingress-nginx/ingress-nginx
```
The output:
```
Release "ingress-nginx" does not exist. Installing it now.
NAME: ingress-nginx
LAST DEPLOYED: Sun Oct 15 12:31:55 2023
NAMESPACE: ingress-nginx
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
The ingress-nginx controller has been installed.
It may take a few minutes for the LoadBalancer IP to be available.
You can watch the status by running 'kubectl --namespace ingress-nginx get services -o wide -w ingress-nginx-controller'

An example Ingress that makes use of the controller:
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
    name: example
    namespace: foo
spec:
    ingressClassName: nginx
    rules:
    - host: www.example.com
        http:
        paths:
            - pathType: Prefix
            backend:
                service:
                name: exampleService
                port:
                    number: 80
            path: /
    # This section is only required if TLS is to be enabled for the Ingress
    tls:
    - hosts:
        - www.example.com
        secretName: example-tls

If TLS is enabled for the Ingress, a Secret containing the certificate and key must also be provided:

apiVersion: v1
kind: Secret
metadata:
    name: example-tls
    namespace: foo
data:
    tls.crt: <base64 encoded cert>
    tls.key: <base64 encoded key>
type: kubernetes.io/tls
```

Verify Installation of helm:
```
$ helm list --filter ingress-nginx --namespace ingress-nginx
NAME         	NAMESPACE    	REVISION	UPDATED                              	STATUS  	CHART              	APP VERSION
ingress-nginx	ingress-nginx	1       	2023-10-15 12:31:55.424517 +0200 CEST	deployed	ingress-nginx-4.8.2	1.9.3
```

Getting svc:
```
$ kubectl get services ingress-nginx-controller --namespace ingress-nginx
NAME                       TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
ingress-nginx-controller   LoadBalancer   10.105.146.129   localhost     80:30769/TCP,443:30327/TCP   2m33s
```

Detect Installed Version:
```
POD_NAME=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx -o jsonpath='{.items[0].metadata.name}')

$ echo ${POD_NAME}
ingress-nginx-controller-667587fcc7-5hh4d

$ kubectl -n ingress-nginx exec -it ${POD_NAME} -- /nginx-ingress-controller --version
-------------------------------------------------------------------------------
NGINX Ingress controller
  Release:       v1.9.3
  Build:         be93503b57a0ba2ea2e0631031541ca07515913a
  Repository:    https://github.com/kubernetes/ingress-nginx
  nginx version: nginx/1.21.6

-------------------------------------------------------------------------------
```

Deploy sample scripts via `kubectl apply`
```
$ kubectl apply -f ./examples
deployment.apps/demo-backend unchanged
service/demo-backend unchanged
deployment.apps/demo-basic-auth unchanged
service/demo-basic-auth unchanged
ingress.networking.k8s.io/demo-ingress created
```

Check deployment status
```
$ kubectl get ingress,service,deployment
NAME                                     CLASS   HOSTS   ADDRESS   PORTS   AGE
ingress.networking.k8s.io/demo-ingress   nginx   *                 80      23s

NAME                      TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/demo-backend      ClusterIP   10.98.244.53    <none>        8088/TCP   96s
service/demo-basic-auth   ClusterIP   10.99.217.200   <none>        80/TCP     96s
service/kubernetes        ClusterIP   10.96.0.1       <none>        443/TCP    10d

NAME                              READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/demo-backend      1/1     1            1           96s
deployment.apps/demo-basic-auth   1/1     1            1           96s
```

## Verification

Expose backend service entries directly with port-forward
```
$ kubectl port-forward service/demo-backend 18088:8088
Forwarding from 127.0.0.1:18088 -> 5678
Forwarding from [::1]:18088 -> 5678
```

Check backend service returns via proxy
```
$ curl -i -u 'user:mysecretpassword' "http://localhost:18088/v1"
HTTP/1.1 200 OK
X-App-Name: http-echo
X-App-Version: 1.0.0
Date: Sun, 15 Oct 2023 10:39:25 GMT
Content-Length: 14
Content-Type: text/plain; charset=utf-8

"hello world"
```

Wait until ingress endpoint become ready (ADDRESS fieled should show ELB address)
```
$ kubectl get ingress
NAME           CLASS   HOSTS   ADDRESS     PORTS   AGE
demo-ingress   nginx   *       localhost   80      2m12s
```

Let's check the responses again with ELB endpoint, HTTPS protocol
```
$ curl -i -u 'user:mysecretpassword' "https://${LOAD_BALANCER}/v1" -k
HTTP/2 200 # <--------------------- Serve with HTTP/2.
date: Fri, 11 Aug 2023 09:30:00 GMT
content-type: text/plain; charset=utf-8
content-length: 14
strict-transport-security: max-age=15724800; includeSubDomains # <--------------------- No sensitive information expose.

"hello world"
```

Let's check the responses again with ELB endpoint, HTTP protocol
```
$ curl -i -u 'user:mysecretpassword' "http://10.105.146.129/v1"
```

Try to modify `ingress.yaml`, and see what's the difference

In this example, response header for the http requests:

- Nginx version is not exposed
- Server information is hidden
- Protected by [ModSecurity](https://modsecurity.org/)
- Protected by Basic DoS Protection

## Cleanup

Cleanup sample scripts via `kubectl delete`
```
$ kubectl delete -f ./examples
deployment.apps "demo-backend" deleted
service "demo-backend" deleted
deployment.apps "demo-basic-auth" deleted
service "demo-basic-auth" deleted
ingress.networking.k8s.io "demo-ingress" deleted
```

Cleanup Nginx Ingress Controller
```
$ helm uninstall ingress-nginx --namespace ingress-nginx
release "ingress-nginx" uninstalled
```

# Reference

- [Nginx-Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [Nginx-Ingress Controller with TLS](https://kubernetes.github.io/ingress-nginx/user-guide/tls/)
- [Nginx Full Configurations Example](https://www.nginx.com/resources/wiki/start/topics/examples/full/)
- [ModSecurity Web Application Firewall](https://kubernetes.github.io/ingress-nginx/user-guide/third-party-addons/modsecurity/)
- [Role-Based Access Control (RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Ingress nginx with basic auth](https://kubernetes.github.io/ingress-nginx/examples/auth/basic/)
- [How to secure Kubernetes Ingress](https://www.armosec.io/blog/kubernetes-ingress-security/)