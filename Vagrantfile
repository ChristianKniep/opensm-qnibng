Vagrant.configure("2") do |config|
  config.vm.box = "centos64"
  config.vm.provision :shell, :path => "bootstrap.sh"
  config.vm.provision :shell, :inline => "echo 'export http_proxy=http://myprox.bull.fr:80' >> /etc/profile.d/proxy.sh"
  config.vm.network :forwarded_port, guest: 80, host: 8080
  
  config.vm.provider "virtualbox" do |v|
    v.name = "opensm-qnibng"
    v.customize ["modifyvm", :id, "--cpuexecutioncap", "50"]
  end
  
end

