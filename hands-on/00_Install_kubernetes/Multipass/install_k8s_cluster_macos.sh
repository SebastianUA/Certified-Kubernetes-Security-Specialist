#!/usr/bin/env bash -x

# CREATED: vitaliy.natarov@yahoo.com
# Unix/Linux blog: http://linux-notes.org

# ------------------------------------------------------------
# Set some colors for status OK, FAIL and titles
SETCOLOR_SUCCESS="echo -en \\033[1;32m"
SETCOLOR_FAILURE="echo -en \\033[1;31m"
SETCOLOR_NORMAL="echo -en \\033[0;39m"

SETCOLOR_TITLE="echo -en \\033[1;36m" 	# Fuscia
SETCOLOR_NUMBERS="echo -en \\033[0;34m" # BLUE

# ------------------------------------------------------------
function preinstall {

	if ! which multipass > /dev/null 2>&1; then
		$SETCOLOR_TITLE
		echo "Install multipass per Unix/Linux OS: https://multipass.run/install"
		$SETCOLOR_NORMAL
		exit -1
	fi

	ssh-keygen -q -N "" -t rsa -b 2048 -C "vmuser" -f ./multipass-ssh-key

	cat << EOF > ./cloud-init.yaml
users:
  - default
  - name: vmuser
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
    - $(cat multipass-ssh-key.pub)
EOF
	
	# cat ./cloud-init.yaml
}

function install_kubemaster01 {

	host_name="kubemaster01"

	# To get images:
	# multipass aliases

	# get_host_status=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}' 2>&1 >/dev/null)
	get_host_status=$(multipass list | grep -Ei "${host_name}" 2>&1 >/dev/null)
	get_host_state=$(multipass list | grep -Ei "${host_name}" | awk '{print $2}')

	if [[ $? == 0 ]] && [[ ${#get_host_status} == 0 ]] && [[ $get_host_state != "Running" ]]; then
		# Install a new host
		multipass launch \
			--name ${host_name} \
			--disk 10G \
			--memory 3G \
			--cpus 2 \
			--network name=en0,mode=manual,mac="52:54:00:4b:ab:cd" \
			--cloud-init cloud-init.yaml \
			noble
	fi
	
	get_host_name=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}')
	get_host_ip=$(multipass info ${host_name} | grep IPv4 | awk '{print $2}')

	$SETCOLOR_SUCCESS
	echo "${get_host_name} - ${get_host_ip}"
	$SETCOLOR_NORMAL
	

	multipass exec -n ${host_name} -- sudo bash -c 'cat << EOF > /etc/netplan/10-custom.yaml
network:
  version: 2
  ethernets:
    extra0:
      dhcp4: no
      match:
        macaddress: "52:54:00:4b:ab:cd"
      addresses: [192.168.73.101/24]
EOF'

	multipass exec -n ${host_name} -- sudo bash -c 'netplan apply 2> /dev/null'
	multipass info ${host_name} | grep IPv4 -A1

}

function install_kubeworker01 {

	host_name="kubeworker01"

	# To get images:
	# multipass aliases

	# get_host_status=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}' 2>&1 >/dev/null)
	get_host_status=$(multipass list | grep -Ei "${host_name}" 2>&1 >/dev/null)
	get_host_state=$(multipass list | grep -Ei "${host_name}" | awk '{print $2}')

	if [[ $? == 0 ]] && [[ ${#get_host_status} == 0 ]] && [[ $get_host_state != "Running" ]]; then
		# Install a new host
		multipass launch \
			--name ${host_name} \
			--disk 10G \
			--memory 3G \
			--cpus 2 \
			--network name=en0,mode=manual,mac="52:54:00:4b:ba:dc" \
			--cloud-init cloud-init.yaml \
			noble
	fi
	
	get_host_name=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}')
	get_host_ip=$(multipass info ${host_name} | grep IPv4 | awk '{print $2}')

	$SETCOLOR_SUCCESS
	echo "${get_host_name} - ${get_host_ip}"
	$SETCOLOR_NORMAL
	

	multipass exec -n ${host_name} -- sudo bash -c 'cat << EOF > /etc/netplan/10-custom.yaml
network:
  version: 2
  ethernets:
    extra0:
      dhcp4: no
      match:
        macaddress: "52:54:00:4b:ba:dc"
      addresses: [192.168.73.102/24]
EOF'

	multipass exec -n ${host_name} -- sudo bash -c 'netplan apply 2> /dev/null'
	multipass info ${host_name} | grep IPv4 -A1
	
}

function install_kubeworker02 {

	host_name="kubeworker02"

	# To get images:
	# multipass aliases

	# get_host_status=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}' 2>&1 >/dev/null)
	get_host_status=$(multipass list | grep -Ei "${host_name}" 2>&1 >/dev/null)
	get_host_state=$(multipass list | grep -Ei "${host_name}" | awk '{print $2}')

	if [[ $? == 0 ]] && [[ ${#get_host_status} == 0 ]] && [[ $get_host_state != "Running" ]]; then
		# Install a new host
		multipass launch \
			--name ${host_name} \
			--disk 10G \
			--memory 3G \
			--cpus 2 \
			--network name=en0,mode=manual,mac="52:54:00:4b:cd:ab" \
			--cloud-init cloud-init.yaml \
			noble
	fi
	
	get_host_name=$(multipass info ${host_name} | grep -Ei "Name" | awk '{print $2}')
	get_host_ip=$(multipass info ${host_name} | grep IPv4 | awk '{print $2}')

	$SETCOLOR_SUCCESS
	echo "${get_host_name} - ${get_host_ip}"
	$SETCOLOR_NORMAL
	

	multipass exec -n ${host_name} -- sudo bash -c 'cat << EOF > /etc/netplan/10-custom.yaml
network:
  version: 2
  ethernets:
    extra0:
      dhcp4: no
      match:
        macaddress: "52:54:00:4b:cd:ab"
      addresses: [192.168.73.103/24]
EOF'

	multipass exec -n ${host_name} -- sudo bash -c 'netplan apply 2> /dev/null'
	multipass info ${host_name} | grep IPv4 -A1
}

function install_k8s_cluster {
	preinstall
	install_kubemaster01
	install_kubeworker01
	install_kubeworker02
	postinstall
}

function configure_k8s_cluster {

	# host_ip_master="192.168.73.101"
	# host_ip_worker1="192.168.73.102"
	# host_ip_worker2="192.168.73.103"

	declare -a StringArray=(
		"kubemaster01"
	  "kubeworker01"
	  "kubeworker02"
	)

	for host in ${StringArray[@]}; do
		multipass exec -n ${host} -- sudo bash -c 'echo "192.168.73.101 kubemaster01" >> /etc/hosts'
		multipass exec -n ${host} -- sudo bash -c 'echo "192.168.73.102 kubeworker01" >> /etc/hosts'
		multipass exec -n ${host} -- sudo bash -c 'echo "192.168.73.103 kubeworker02" >> /etc/hosts'

		multipass exec -n ${host} -- sudo bash -c 'echo "overlay" >> /etc/modules-load.d/k8s.conf'
		multipass exec -n ${host} -- sudo bash -c 'echo "br_netfilter" >> /etc/modules-load.d/k8s.conf'
		multipass exec -n ${host} -- sudo bash -c 'modprobe overlay 2> /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'modprobe br_netfilter 2> /dev/null'

		multipass exec -n ${host} -- sudo bash -c 'cat << EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF'

		multipass exec -n ${host} -- sudo bash -c 'echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf'
		multipass exec -n ${host} -- sudo bash -c 'sysctl -p'

		multipass exec -n ${host} -- sudo bash -c 'lsmod | grep br_netfilter 2> /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'lsmod | grep overlay 2> /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward 2> /dev/null'

		# TODO: Install containerd
		multipass exec -n ${host} -- sudo bash -c 'curl -LOs https://github.com/containerd/containerd/releases/download/v1.7.21/containerd-1.7.21-linux-arm64.tar.gz'
		multipass exec -n ${host} -- sudo bash -c 'curl -LOs https://raw.githubusercontent.com/containerd/containerd/main/containerd.service'
		multipass exec -n ${host} -- sudo bash -c 'tar Cxzvf /usr/local containerd-1.7.21-linux-arm64.tar.gz'
		multipass exec -n ${host} -- sudo bash -c 'mkdir -p /usr/local/lib/systemd/system/'
		multipass exec -n ${host} -- sudo bash -c 'mv containerd.service /usr/local/lib/systemd/system/'
		multipass exec -n ${host} -- sudo bash -c 'mkdir -p /etc/containerd/'
		multipass exec -n ${host} -- sudo bash -c 'containerd config default | tee /etc/containerd/config.toml > /dev/null'
		multipass exec -n ${host} -- sudo bash -c "sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml"

		multipass exec -n ${host} -- sudo bash -c 'systemctl daemon-reload'
		multipass exec -n ${host} -- sudo bash -c 'systemctl enable --now containerd'
		# multipass exec -n ${host} -- sudo bash -c 'systemctl status containerd'
		

		# Install runc
		multipass exec -n ${host} -- sudo bash -c 'curl -LOs https://github.com/opencontainers/runc/releases/download/v1.1.13/runc.arm64'
		multipass exec -n ${host} -- sudo bash -c 'install -m 755 runc.arm64 /usr/local/sbin/runc 2> /dev/null'


		# Install CNI plugins
		multipass exec -n ${host} -- sudo bash -c 'curl -LOs https://github.com/containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-arm64-v1.5.1.tgz'
		multipass exec -n ${host} -- sudo bash -c 'mkdir -p /opt/cni/bin'
		multipass exec -n ${host} -- sudo bash -c 'tar Cxzvf /opt/cni/bin cni-plugins-linux-arm64-v1.5.1.tgz'


		# TODO: Install kubeadm, kubelet and kubectl
		multipass exec -n ${host} -- sudo bash -c 'apt-get update > /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'apt-get install -y apt-transport-https ca-certificates curl gpg > /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg'
		multipass exec -n ${host} -- sudo bash -c "echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list"
		multipass exec -n ${host} -- sudo bash -c 'apt-get update > /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'apt-get install -y kubelet kubeadm kubectl 2> /dev/null'
		multipass exec -n ${host} -- sudo bash -c 'apt-mark hold kubelet kubeadm kubectl 2> /dev/null'  


		# Configure crictl to work with containerd
		multipass exec -n ${host} -- sudo bash -c 'crictl config runtime-endpoint unix:///var/run/containerd/containerd.sock'
	done;

	# Configure controlplane node
	multipass exec -n kubemaster01 -- sudo bash -c 'kubeadm init --pod-network-cidr=10.244.0.0/16 --apiserver-advertise-address=192.168.73.101' 

	multipass exec -n kubemaster01 -- sudo bash -c 'mkdir -p $HOME/.kube'
	multipass exec -n kubemaster01 -- sudo bash -c 'cp -i /etc/kubernetes/admin.conf $HOME/.kube/config'
	multipass exec -n kubemaster01 -- sudo bash -c 'chown $(id -u):$(id -g) $HOME/.kube/config'

	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl -n kube-system get pods'
	# TODO: add/replace to cilium
	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl apply -f https://reweave.azurewebsites.net/k8s/v1.30/net.yaml'
	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl -n kube-system get pods'

	multipass exec -n kubemaster01 -- sudo bash -c 'kubeadm token create --print-join-command' > worker_join_command.sh
	multipass exec -n kubemaster01 -- sudo bash -c 'cat /etc/kubernetes/admin.conf' > kubeconfig


	# Configure workers 
	multipass transfer worker_join_command.sh kubeworker01:
	multipass transfer worker_join_command.sh kubeworker02:

	multipass exec -n kubeworker01 -- sudo bash -c 'bash ./worker_join_command.sh'
	multipass exec -n kubeworker02 -- sudo bash -c 'bash ./worker_join_command.sh'

	multipass transfer kubeconfig kubeworker01:
	multipass transfer kubeconfig kubeworker02:

	multipass exec -n kubeworker01 -- sudo bash -c 'rm -rf ~/.kube && mkdir ~/.kube && mv ./kubeconfig ~/.kube/config'
	multipass exec -n kubeworker02 -- sudo bash -c 'rm -rf ~/.kube && mkdir ~/.kube && mv ./kubeconfig ~/.kube/config'

	# Check nodes
	# rm -f worker_join_command.sh
	# rm -f kubeconfig
	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl get nodes'
}

function postinstall {
	
	declare -a StringArray=(
		"kubemaster01"
	  "kubeworker01"
	  "kubeworker02"
	)

	for host in ${StringArray[@]}; do
		multipass exec -n ${host} -- sudo bash -c 'apt install bash-completion -y'
		multipass exec -n ${host} -- sudo bash -c 'kubectl completion bash | tee /etc/bash_completion.d/kubectl > /dev/null'
		multipass exec -n ${host} -- sudo bash -c "echo 'alias k=kubectl' >> ~/.bashrc"
		multipass exec -n ${host} -- sudo bash -c "echo 'complete -o default -F __start_kubectl k' >> ~/.bashrc"
	done

	$SETCOLOR_SUCCESS
	echo "Tune SSH"
	$SETCOLOR_NORMAL

	# TODO: 
		# https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-20-04
		# https://hostman.com/tutorials/how-to-install-and-configure-ssh-on-an-ubuntu-server/

	# apt install openssh-server -y
	# Edit /etc/ssh/sshd_config
	# #PubkeyAuthentication yes

	# systemctl restart ssh

}

function generate_context {
	$SETCOLOR_SUCCESS
	echo "Generate kube-context for local usages"
	$SETCOLOR_NORMAL

 	multipass exec -n kubemaster01 -- sudo bash -c "kubectl create clusterrolebinding cluster-admin-vmuser@kubernetes.local --user=vmuser@kubernetes.local --clusterrole='cluster-admin' --group='admins'"

	openssl genrsa -out vmuser.key 2048
	openssl req -new -key vmuser.key -out vmuser.csr -subj "/CN=vmuser@kubernetes.local"

	cat << EOF > ./vmuser-csr.yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: vmuser@kubernetes.local
spec:
  request: $(cat ./vmuser.csr | base64)
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages:
  - client auth
EOF

	multipass transfer vmuser-csr.yaml kubemaster01:
	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl create -f vmuser-csr.yaml'
	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl certificate approve vmuser@kubernetes.local'
 	multipass exec -n kubemaster01 -- sudo bash -c 'kubectl get csr vmuser@kubernetes.local -ojsonpath="{.status.certificate}" | base64 -d > vmuser.crt'
	multipass transfer kubemaster01:vmuser.crt ./vmuser.crt

	# multipass exec -n kubemaster01 -- sudo bash -c "kubectl get cm -o jsonpath='{.items[0].data.ca\.crt}' > kubernetes.ca.crt"
	# multipass transfer kubemaster01:kubernetes.ca.crt ./kubernetes.ca.crt
	# kubectl config set-cluster kubernetes.local --server=https://192.168.64.18 --certificate-authority="$(pwd)/kubernetes.ca.crt"

	get_host_ip=$(multipass info kubemaster01 | grep IPv4 | awk '{print $2}')

	kubectl config set-cluster kubernetes.local --server=https://${get_host_ip}:6443 --insecure-skip-tls-verify=true
	kubectl config set-credentials vmuser@kubernetes.local --client-key=vmuser.key --client-certificate=vmuser.crt --username='vmuser@kubernetes.local'
 	kubectl config set-context vmuser@kubernetes.local --cluster=kubernetes.local --user=vmuser@kubernetes.local
 	kubectl config use-context vmuser@kubernetes.local
 	kubectl get ns && kubectl get po
}

function status_all {
	declare -a StringArray=(
		"kubemaster01"
	  "kubeworker01"
	  "kubeworker02"
	)

	for host in ${StringArray[@]}; do
		get_host_state=$(multipass list | grep -Ei "${host}" | awk '{print $2}')

		$SETCOLOR_SUCCESS
		echo "The ${host} has ${get_host_state} at this moment"
		$SETCOLOR_NORMAL
	done

	echo -e "\nTo connect to host use SSH, for example: \n"
	echo "ssh vmuser@192.168.73.101 -i ./multipass-ssh-key -o StrictHostKeyChecking=no"
	echo "ssh vmuser@192.168.73.102 -i ./multipass-ssh-key -o StrictHostKeyChecking=no"
	echo "ssh vmuser@192.168.73.103 -i ./multipass-ssh-key -o StrictHostKeyChecking=no"
}

function start_all {
	declare -a StringArray=(
		"kubemaster01"
	  "kubeworker01"
	  "kubeworker02"
	)

	for host in ${StringArray[@]}; do
		get_host_state=$(multipass list | grep -Ei "${host}" | awk '{print $2}')

		if [[ "$get_host_state" =~ ^(Stopped|Suspended)$ ]]; then
			multipass start ${host}
		else
			echo "The ${host} has ${get_host_state} at this moment"
		fi
	done

	multipass list
}

function stop_all {
	declare -a StringArray=(
	  "kubeworker02"
	  "kubeworker01"
	  "kubemaster01"
	)

	for host in ${StringArray[@]}; do
		get_host_state=$(multipass list | grep -Ei "${host}" | awk '{print $2}')

		if [[ "$get_host_state" =~ ^(Running)$ ]]; then
			multipass stop ${host}
		else
			echo "The ${host} has ${get_host_state} at this moment"
		fi
	done

	multipass list
}

function snapshot_all {
	declare -a StringArray=(
	  "kubeworker02"
	  "kubeworker01"
	  "kubemaster01"
	)

	for host in ${StringArray[@]}; do
		get_host_state=$(multipass list | grep -Ei "${host}" | awk '{print $2}')

		if [[ "$get_host_state" =~ ^(Running)$ ]]; then
			multipass snapshot ${host}
		else
			echo "The ${host} has ${get_host_state} at this moment"
		fi
	done

	multipass list --snapshots
}

function uninstall_all {
	declare -a StringArray=(
	  "kubeworker02"
	  "kubeworker01"
	  "kubemaster01"
	)

	for host in ${StringArray[@]}; do
		multipass delete ${host}
	done

	multipass purge
}

# ------------------------------------------------------------
case "$1" in
	preinstall)
    preinstall
    ;;
	install_k8s_cluster|install_k8s|install)
    install_k8s_cluster
		configure_k8s_cluster
		generate_context
    ;;
  postinstall)
    postinstall
    ;;
  generate_context|get_context|context)
    generate_context
    ;;
  status_all|status)
    status_all
    ;;
  start_all|start)
    start_all
    ;;
  stop_all|stop)
    stop_all
    ;;
  help|h|-h)
		$SETCOLOR_NUMBERS
		echo "Set 'preinstall' as ARG to pre-install some stuff for K8S cluster"
    echo "Set 'install' as ARG to install K8S cluster"
    echo "Set 'postinstall' as ARG to postinstall something else"
    echo "Set 'context' as ARG to postinstall something else"
    echo "Set 'status' as ARG to get status of K8S cluster"
    echo "Set 'start' as ARG to start K8S cluster"
    echo "Set 'stop' as ARG to start K8S cluster"
    echo "Set 'snapshot_all' as ARG to create snapshots"
    $SETCOLOR_NORMAL
    ;;
  *)
		$SETCOLOR_TITLE
    echo "Use 'help' to get help!"
    $SETCOLOR_NORMAL
    ;;
esac

$SETCOLOR_SUCCESS
echo "# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "#                              Finish!							 	                 "
echo "# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
$SETCOLOR_NORMAL
