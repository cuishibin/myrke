package main

import (
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"fmt"
	"os"
	"regexp"
	"sort"
)

func PrintHelp(){
	fmt.Println("./cluster <ip>")
	fmt.Println("example: ./cluster 10.12.1.110")
}

func main() {
  if len(os.Args) != 2 {
  	PrintHelp()
  	return
  }

  ip := os.Args[1]

  // ip check
  pattern := "[\\d]+\\.[\\d]+\\.[\\d]+\\.[\\d]+"
  matchIp, _ := regexp.MatchString(pattern, ip)
  if !matchIp {
  	fmt.Println("please input correct ip address.")
  	return
  }
    
  fmt.Println("ip:", ip)
  
  var c conf
  c.getConf()
  c.writeFile("cluster.yml.bak")

  c.AddWorker(ip)
  c.writeFile("cluster.yml")
}

type conf struct {
	Nodes                 []Node
	Services              Services
	Network               Network
	Authentication        Authentication
	Addons                string
	Addons_include        []string
	System_images         System_images
	Ssh_key_path          string
	Ssh_agent_auth        bool
	Authorization         Authorization
	Ignore_docker_version bool
	Kubernetes_version    string
	Private_registries    []string
	Ingress               Ingress
	Cluster_name          string
	Cloud_provider        Cloud_provider
	Prefix_path           string
	Addon_job_timeout     int
	Bastion_host          Bastion_host
}
// -------------------------------------------------------------------------
// node
// -------------------------------------------------------------------------
type Node struct{
	Address string
	Port string
	Internal_address string
	Role []string
	Hostname_override string
	User string
	Docker_socket string
	Ssh_key string
	Ssh_key_path string
	Labels map[string]string
}
type Nodes []Node
func (ns Nodes) Len() int {
	return len(ns)
}
func (ns Nodes) Less(i, j int) bool {
	return ns[i].Address < ns[j].Address
}
func (ns Nodes) Swap(i,j int) {
	ns[i].Address, ns[j].Address = ns[j].Address, ns[i].Address
	ns[i].Port, ns[j].Port = ns[j].Port, ns[i].Port
	ns[i].Internal_address, ns[j].Internal_address = ns[j].Internal_address, ns[i].Internal_address
	ns[i].Role, ns[j].Role = ns[j].Role, ns[i].Role
	ns[i].Hostname_override, ns[j].Hostname_override = ns[j].Hostname_override, ns[i].Hostname_override
	ns[i].User, ns[j].User = ns[j].User, ns[i].User
	ns[i].Docker_socket, ns[j].Docker_socket = ns[j].Docker_socket, ns[i].Docker_socket
	ns[i].Ssh_key, ns[j].Ssh_key = ns[j].Ssh_key, ns[i].Ssh_key
	ns[i].Ssh_key_path, ns[j].Ssh_key_path = ns[j].Ssh_key_path, ns[i].Ssh_key_path
	ns[i].Labels, ns[j].Labels = ns[j].Labels, ns[i].Labels
}
// -------------------------------------------------------------------------
// services
// -------------------------------------------------------------------------
type Services struct{
	Etcd Etcd
	Kubeapi Kubeapi `yaml:"kube-api"`
	Kubecontroller Kubecontroller `yaml:"kube-controller"`
	Scheduler Scheduler
	Kubelet Kubelet
	Kubeproxy Kubeproxy
}

type Etcd struct{
	Image string
	Extra_args map[string]string
	Extra_binds []string
	Extra_env []string
	External_urls []string
	Ca_cert string
	Cert string
	Key string
	Path string
	Snapshot bool
	Retention string
	Creation string
}

type Kubeapi struct{
	Image string
	Extra_args map[string]string
	Extra_binds []string
	Extra_env []string
	Service_cluster_ip_range string
	Service_node_port_range string
	Pod_security_policy bool
}

type Kubecontroller struct{
	Image string
	Extra_args map[string]string
	Extra_binds []string
	Extra_env []string
	Cluster_cidr string
	Service_cluster_ip_range string
}

type Scheduler struct{
	Image string
	Extra_args map[string]string
	Extra_binds []string
	Extra_env []string
}

type Kubelet struct{
	Image string
	Extra_args map[string]int
	Extra_binds []string
	Extra_env []string
	Cluster_domain string
	Infra_container_image string
	Cluster_dns_server string
	Fail_swap_on bool
}

type Kubeproxy struct{
	Image string
	Extra_args map[string]string
	Extra_binds []string
	Extra_env []string
}

// -------------------------------------------------------------------------
// others
// -------------------------------------------------------------------------
type Network struct{
	Plugin string
	Options map[string]string
}
type Authentication struct{
	Strategy string
	Options map[string]string
	Sans []string
}
type System_images struct{
	Etcd                        string
	Alpine                      string
	Nginx_proxy                 string
	Cert_downloader             string
	Kubernetes_services_sidecar string
	Kubedns                     string
	Dnsmasq                     string
	Kubedns_sidecar             string
	Kubedns_autoscaler          string
	Kubernetes                  string
	Flannel                     string
	Flannel_cni                 string
	Calico_node                 string
	Calico_cni                  string
	Calico_controllers          string
	Calico_ctl                  string
	Canal_node                  string
	Canal_cni                   string
	Canal_flannel               string
	Wave_node                   string
	Weave_cni                   string
	Pod_infra_container         string
	Ingress                     string
	Ingress_backend             string
}
type Authorization struct{
	Mode    string
	Options map[string]string
}
type Ingress struct{
	Provider string
	Options map[string]string
	Node_selector map[string]string
	Extra_args map[string]string
}
type Cloud_provider struct{
	Name string
}
type Bastion_host struct{
	Address string
	Port string
	User string
	Ssh_key string
	Ssh_key_path string
}

func (c *conf) getConf() {
    yamlFile, err := ioutil.ReadFile("cluster.yml")
    if err != nil {
        fmt.Println(err.Error())
    }
    err = yaml.Unmarshal(yamlFile, c)
    if err != nil {
        fmt.Println(err.Error())
    }
}

// -------------------------------------------------------------------------
// add worker node
// -------------------------------------------------------------------------
func (c *conf) AddWorker(ip string) bool {
	if c.checkExist(ip) == false  {
		var n Node
		n.Address = ip
		n.Port = "22"
		n.Internal_address = ""
		n.Role = []string{"worker"}
		n.Hostname_override = ""
		n.User = "docker"
		n.Docker_socket = "/var/run/docker.sock"
		n.Ssh_key = ""
		n.Ssh_key_path = "~/.ssh/id_rsa"
		n.Labels = nil
		c.Nodes = append(c.Nodes, n)
		fmt.Println("ip:", ip, " added!")
		return true
	}
	fmt.Println("ip:", ip, " already exists!")
	return  false
}

// check ip exist
func (c *conf) checkExist(ip string) bool{
	a_len := len(c.Nodes)
	for i := 0; i < a_len; i++ {
		if (c.Nodes[i].Address == ip) {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------
// write to file
// -------------------------------------------------------------------------
func (c *conf) writeFile(file_name string){
	sort.Sort(Nodes(c.Nodes))
	d, err := yaml.Marshal(&c)
	if err != nil {
		fmt.Println(err.Error())
	}
	ioutil.WriteFile(file_name, d, 0644)
}