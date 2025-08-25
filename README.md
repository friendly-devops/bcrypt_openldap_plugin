# bcrypt_openldap_plugin
The bcrypt_openldap_plugin repo is to provide a plugin module for the purposes of enabling the ability to encrypt and decrypt bcrypt encoding in OpenLDAP 

## Build details

### Build OpenLDAP
Build and install OpenLDAP from https://github.com/openldap/openldap

with the below arguments:

    ./configure --enable-modules --enable-slapd
    make depend
    make
    sudo su root -c 'make install'

### Build Bcrypt Plugin Module
    cd contrib/slapd-modules/passwd
    git clone https://github.com/friendly-devops/bcrypt_openldap_plugin.git
    cd bcrypt_openldap_plugin
    make
    sudo make install

### Add Module to Slapd Configuration
add the line:

    moduleload bcrypt_plugin.la
    password-hash {BCRYPT}

Add a integer between 4 and 31 as an argument to the end of the moduleload line to alter the workfactor the default is set to 8.
Restart slapd

    sudo /usr/local/libexec/slapd

### Test Hash Generation
    slappasswd -o module-path=/usr/local/libexec/openldap -o module-load="bcrypt_plugin.la <int>" -h {BCRYPT} -s secret
Set the workfactor in the above command by changing the <int> to an integer from 4 to 31 or removing it to use the default workfactor
