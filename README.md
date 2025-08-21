# bcrypt_openldap_plugin
The bcrypt_openldap_plugin repo is to provide a plugin module for the purposes of enabling the ability to encrypt and decrypt bcrypt encoding in OpenLDAP 

## Build details
### Build OpenLDAP
Build and install OpenLDAP from 
with the below arguments
    ./configure --prefix=/usr/local --enable-modules
    make depend
    sudo make install

### Build Bcrypt Plugin Module
    cd contrib/slapd-modules/passwd
    git clone https://github.com/friendly-devops/bcrypt_openldap_plugin?tab=GPL-2.0-1-ov-file bcrypt
    cd bcrypt
    make
    sudo make install

### Add Module to Slapd Configuration
add the line:
    moduleload /usr/local/libexec/openldap/bcrypt_plugin.so
    password-hash {BCRYPT}
Add a integer between 4 and 31 as an argument to the end of the moduleload line to alter the workfactor the default is set to 8.
Restart slapd
    sudo systemctl restart slapd

### Test Hash Generation
    slappasswd -o module-path=/usr/local/libexec/openldap -o module-load="bcrypt_plugin.la <int>" -h {BCRYPT} -s secret
Set the workfactor in the above command by changing the <int> to an integer between 4 and 31
