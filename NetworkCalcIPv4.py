import re

class NetworkCalcIPv4():

    def __init__(self, network, netmask = None):
        """Initialize the class.

        Keyword arguments:
        network -- network address with optional cidr-suffix
        netmask -- netmask of the network, mandatory if cidr in network is missing (default None)
        """

        # split netword and cidr if possible
        if '/' in network:

            # cidr is present, split string at '/'
            splitted_input = network.split('/')

            # make further checks to verify that input is valid
            if len(splitted_input) != 2:
                raise ValueError('Given Network/CIDR-String not valid')

            if not self.__validate_ipv4(splitted_input[0]):
                raise ValueError('Network not valid')

            if not self.__validate_cidr(splitted_input[1]):
                raise ValueError('CIDR not valid')

            # if all checks are successful the input can be saved
            self.__network_id = splitted_input[0]
            self.__cidr = int(splitted_input[1])
            self.__netmask = self.__cidr_to_netmask(self.__cidr)

        else:
            
            # cidr not present, make sure that input is valid
            if not self.__validate_ipv4(network):
                raise ValueError('Network not valid')

            if netmask == None:
                raise ValueError('Netmask or CIDR is missing')

            if not self.__validate_netmask(netmask):
                raise ValueError('Netmask invalic')

            # if all checks are successful the input can be saved
            self.__network_id = network
            self.__cidr = self.__netmask_to_cidr(netmask)
            self.__netmask = netmask

        # calculating additional information
        self.__hosts = []
        self.__calc_hosts()

    def __str__(self):
        final_str =              f'Network ID   : {self.__network_id}'
        final_str = f'{final_str}\nCIDR-Suffix  : {self.__cidr}'
        final_str = f'{final_str}\nNetmask      : {self.__netmask}'
        final_str = f'{final_str}\nInv Netmask  : '
        final_str = f'{final_str}\nHosts        : {len(self.__hosts)}'
        final_str = f'{final_str}\nActive Hosts : '
        final_str = f'{final_str}\nFirst Host   : {self.__hosts[0]}'
        final_str = f'{final_str}\nLast Host    : {self.__hosts[-1]}'
        final_str = f'{final_str}\nBroadcast    : {self.__broadcast}'

        return final_str

    def __validate_ipv4(self, ipv4):
        """validates if the given input is a valid ipv4 address.

        Keyword arguments:
        ipv4 -- ipv4 address
        """

        # basic regular expression for ipv4 address
        exp = r'^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$'

        # check if regular expression fits on network
        if re.match(exp, ipv4):

            # check if each octet (as decimal) is between 0 and 255
            for octet in ipv4.split('.'):
                if int(octet) > 255 or int(octet) < 0:
                    return False
            return True
        return False

    def __validate_netmask(self, netmask):
        """validates if the given input is a valid netmask.

        Keyword arguments:
        netmask -- ipv4 netmask
        """

        # check if valid ipv4
        if not self.__validate_ipv4(netmask):
            raise ValueError('Invalid Netmask')

        # check that every octet has a valid decimal number
        possible_values = ['255','254','252','248','240','224','192','128','0']
        for octet_decimal in netmask.split('.'):
            if octet_decimal not in possible_values:
                return False

        # chat that after an octec smaller than 255 only 0 can follow
        only_0_allowed = False
        for octet_decimal in netmask.split('.'):
            if only_0_allowed:
                if octet_decimal != '0':
                    return False
            if octet_decimal != '255':
                only_0_allowed = True
            
        return True

    def __validate_cidr(self, cidr):
        """validates if the given input is a valid ipv4 address.

        Keyword arguments:
        cidr -- cidr-suffix
        """
        if int(cidr) < 1 or int(cidr) > 31:
            return False
        return True

    def __validate_binary(self, binary):
        """validates if the given input is a valid binary string.

        Keyword arguments:
        binary -- binary string
        """

        # basic regular expression for binary string
        exp = r'^[01]+$'

        # check if regular expression fits on string
        if re.match(exp, binary):
            return True
        return False

    def __binary_to_ipv4(self, binary):
        """Calculates the ipv4 for the 32-bit binary string

        Keyword arguments:
        binary -- 32-bit binary
        """

        # check if input is a valid binary string that is not longer than 32 char
        if not self.__validate_binary(binary) or len(binary) != 32:
            raise ValueError('Not a binary string containing only 0 and 1 or not 32 chars')

        # get the octets from the string
        octets = [binary[0:8], binary[8:16], binary[16:24], binary[24:32]]
        octets_dec = []

        # calculate the decimal number for each octet
        for i in range(0,4):
            # this holds the decimal sum for each octet
            sum_octet = 0

            # calculate the current power for the binary system (1,2,4,8,46,32,64,128)
            # and multiply it with the current binary char of the string which is read
            # from right to left
            for z in range(0,8):
                sum_octet += int(octets[i][::-1][z]) * int((2**(z+1))/2)

            # append the calculated sum
            octets_dec.append(sum_octet)

        # build the return string
        return f'{str(octets_dec[0])}.{str(octets_dec[1])}.{str(octets_dec[2])}.{str(octets_dec[3])}'

    def __binary_to_cidr(self, binary):
        """Calculates the decimal cidr for a binary cidr string

        Keyword arguments:
        binary -- (32-bit) binary
        """

        # check if input is a valid binary string that is not longer than 32 char
        if not self.__validate_binary(binary) or len(binary) > 32:
            raise ValueError('Not a binary string containing only 0 and 1 or bigger than 32 chars')

        # count all leading ones
        decimal_cidr = 0
        for char in binary:
            if char == '1':
                decimal_cidr += 1
            else:
                break

        return decimal_cidr

    def __ipv4_to_binary(self, ipv4):
        """Calculates the binary 32-bit pattern of a given ipv4 address

        Keyword arguments:
        ipv4 -- ipv4 address
        """

        # check if input is valid
        if not self.__validate_ipv4(ipv4):
            raise ValueError('Not a valid IPv4 Address')

        binary_string = ''

        # calculate binary for each octet and append it to the binary_string
        for octet in ipv4.split('.'):
            current_value = int(octet)
            current_bin = ''

            while current_value > 0:
                current_bin = str(current_value % 2) + current_bin
                current_value = current_value // 2

            binary_string = binary_string + '{:0>8}'.format(current_bin)

        # return the calculated 32-bit string
        return binary_string

    def __cidr_to_binary(self, cidr):
        """Calculates the binary for the cidr-suffix

        Keyword arguments:
        cidr -- cidr-suffix
        """

        # validate cidr
        if not self.__validate_cidr(cidr):
            raise ValueError('CIDR not valid')

        # calculate the binary cidr
        cidr_bin = ''
        for i in range(1, int(cidr)+1):
            cidr_bin = cidr_bin + '1'

        # fill the remaining space with 0 to get 32-bit
        cidr_bin = '{:0<32}'.format(cidr_bin)

        return cidr_bin
    
    def __cidr_to_netmask(self, cidr):
        """Calculates the subnetmask for the cidr-suffix

        Keyword arguments:
        cidr -- cidr-suffix
        """

        # calculate the netmask for the cidr
        netmask = self.__binary_to_ipv4(self.__cidr_to_binary(cidr))
        
        return netmask

    def __netmask_to_cidr(self, netmask):
        """Calculates the cidr-suffix for the subnetmask

        Keyword arguments:
        netmask -- netmask ipv4
        """

        cidr = self.__binary_to_cidr(self.__ipv4_to_binary(netmask))

        return cidr

    def __calc_hosts(self):
        """Calculates the Broadcast Address and every host address for this network.

        Keyword arguments:
        None
        """

        # calculate amount of ip-addresses (including network id an broadcast)
        host_bits = 32 - self.__cidr
        sum_hosts = 2**host_bits

        # cut the binary network part from network id
        net_bin = self.__ipv4_to_binary(self.__network_id)[:-host_bits]

        # count binary from 0 to sum_hosts
        leading_zeros = '{:0>'+str(host_bits)+'}'
        for i in range(0,sum_hosts,1):
            current_bin = leading_zeros.format(str(format(i, 'b')))
            if i == 0:
                # this is the network id - ignore
                print('Network:'+self.__binary_to_ipv4(net_bin + current_bin))
            elif i == sum_hosts-1:
                # this is the broadcast ip
                self.__broadcast = self.__binary_to_ipv4(net_bin + current_bin)
            else:
                # this is a host address
                self.__hosts.append(self.__binary_to_ipv4(net_bin + current_bin))

if __name__ == '__main__':
    my_network = NetworkCalcIPv4('192.168.5.0/24')
    my_network2 = NetworkCalcIPv4('192.168.178.0', '255.255.252.0')
    print(my_network)
    print('-'*10)
    print(my_network2)