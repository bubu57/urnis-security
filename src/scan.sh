green=$(tput setaf 2)
red=$(tput setaf 1)
normal=$(tput sgr0)

BLEU='\033[0;34m'
GREEN='\033[0;32m'
LGREY='\033[0;37m'
RED='\033[0;31m'
NC='\033[0m'

total_file=0
suspect_file=0
hashfile="/usr/share/urnis/src/MD5Hahses.txt"
file_path="/usr/share/urnis/src/dir.txt"
while read -r line; do
    if [ -d "$line" ]; then
        printf "%-47s" "   - Checking $line"
        if [ ! -f "$hashfile" ]; then
            echo "Hash file list not found"
            exit 1
        fi
        for file in "$line"/*; do
            if [ -d "$file" ]; then
                echo -n
            else
                file_hash=$(md5sum "$file" | cut -d' ' -f1)
                match=$(grep "$file_hash" "$hashfile")
                if [ -z "$match" ]; then
                    ((total_file=total_file+1))
                else
                    ((suspect_file=suspect_file+1))
                fi
            fi
        done
        if [ "${suspect_file}" = 0 ]; then
            echo "${GREEN}OK${NC}"
        else
            echo "${RED}FOUND${NC}"
        fi
    else
        printf "%-47s %s\n" "   - Checking $line" "${red}NOT FOUND${normal}"
        
    fi
done < "$file_path"
((total_file=total_file+suspect_file))