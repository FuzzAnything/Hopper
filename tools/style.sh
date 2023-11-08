RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN="\033[1;32m"
NC='\033[0m' # No Color

# determine if the output is on a terminal
# if so, output colored text
# otherwise output plain text
output_is_terminal() {
    if [ -t 1 ]; then
        return 0
    else
        return -1
    fi
}

info() {
    if output_is_terminal; then
        printf "${GREEN}[+] $@${NC}\n"
    else 
        printf $@
    fi;
}

warn() {
    if output_is_terminal; then
        printf "${YELLOW}[-] $@${NC}\n"
    else
        printf $@
    fi;
}

error() {
    if output_is_terminal; then
        printf "${RED}[x] $@${NC}\n"
    else 
        printf $@
    fi;
}
