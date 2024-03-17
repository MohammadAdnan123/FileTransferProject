
import subprocess,ipaddress,socket,platform

def same_network(ip1, cidr1, ip2, cidr2):
    try:
        # Create IP network objects from the IP addresses and CIDR notations
        network1 = ipaddress.ip_network(ip1 + cidr1, strict=False)
        network2 = ipaddress.ip_network(ip2 + cidr2, strict=False)
        
        # Check if the networks are the same
        return network1.network_address == network2.network_address and \
               network1.prefixlen == network2.prefixlen
    except ValueError as e:
        print("Error:", e)
        return False

# I have check the users are from the same network or not by providing first user details 
# These are sample ip address of first user 
ip1 = "10.128.2.58"
cidr1 = "/20"

# Get the operating system name platform module
os_name = platform.system()

if os_name in ('Darwin','Linux'):
    def get_ip_address():
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
            # Connect to any remote server, it doesn't matter which
            s.connect(("8.8.8.8", 80))
        
            # Get the IP address
            ip_address = s.getsockname()[0]
        
            # Close the socket
            s.close()
        
            return ip_address
        except socket.error:
            return None
    def get_subnet_mask(interface_name='en0'):
          try:
              
              # Execute ifconfig command to get interface information
              output = subprocess.check_output(['ifconfig', interface_name])
              # Convert the output to string and split it by lines
              output = output.decode('utf-8').split('\n')
              # Search for the subnet mask line
              for line in output:
                    if 'netmask' in line:
                        # Extract the subnet mask from the line
                        subnet_mask = line.split('netmask ')[1].split(' ')[0]
                        return subnet_mask
              return "Subnet mask not found for interface {}".format(interface_name)
          except subprocess.CalledProcessError as e:
              return "Error: {}".format(e)
    # We need to convert hexadecimal representation of subnet mask to CIDR notation to make simple

    def hex_to_cidr(subnet_mask):
        
        # Convert hexadecimal mask to binary
        binary_mask = bin(int(subnet_mask, 16))[2:].zfill(32)
        # Count the number of '1's in the binary mask
        prefix_length = binary_mask.count('1')
        return '/' + str(prefix_length)
    
    subnet_mask = get_subnet_mask()

    cidr2 = hex_to_cidr(subnet_mask)
    
    # Getting  the IP address of the user
    ip2 = get_ip_address()
    
elif os_name =='Windows':
    def get_user_ip():
          #obtain the ip address of the client by using gethostbyname function available in socket module
          return socket.gethostbyname(socket.gethostname())
    def get_subnet_mask():
        try:
            
            # Run the 'ipconfig' command in the shell
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        
            # Parse the output to find the subnet mask
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if 'Subnet Mask' in line:
                    subnet_mask_str = line.split(':')[1].strip()
                    subnet_mask = ipaddress.IPv4Address(subnet_mask_str)
                    return str(subnet_mask)
        
            return None
        except Exception as e:
            print("Error:", e)
            return None
    def decimal_to_cidr(subnet_mask):
        # Convert the subnet mask to a list of binary octets
        binary_octets = ''.join([bin(int(octet))[2:].zfill(8) for octet in subnet_mask.split('.')])

        # Count the number of consecutive 1 bits
        cidr = binary_octets.count('1')
        
        return '/' + str(cidr)



    # Getting and printing the subnet mask
    subnet_mask = get_subnet_mask()
    if subnet_mask:
        print("Subnet Mask:", subnet_mask)
    else:
        print("Failed to retrieve subnet mask.")

    ip2= get_user_ip()
    cidr2 = decimal_to_cidr(subnet_mask)

if same_network(ip1, cidr1, ip2, cidr2):
    print("Both users are from the same network.")
else:
    print("Users are not from the same network.")
