require "http/client"
require "option_parser"
require "regex/match_data"
require "json"

destination = ""
file_path = ""

OptionParser.parse do |parser|
    parser.on("-c NAME","Single CVE | Multiple CVE-s separated with ',' -> -c CVE-XXX-XXXX,CVE-XXX-XXXX,CVE-XXX-XXXX"){|name| destination = name}
    parser.on("-r PATH","Get CVE-s from Retire_JS.html output"){|path| file_path = path}
    parser.on("-h", "--help", "e.g. ./CVEcrystalyer -r retire_js.html | ./CVEcrystalyer -c CVE-2020-11022") do
        puts parser
        exit
    end
    parser.invalid_option do |flag|
        STDERR.puts "ERROR: #{flag} is not a valid option."
        STDERR.puts parser
        exit(1)
      end
end

## IMPORT FILE
if file_path != ""
    file = File.new(file_path)
    content = file.gets_to_end
    file.close

    #retire js regex
    match1 = content.scan(/<td>(CVE-.*?-.*?) /).map &.[1]
    match2 = content.scan(/ (CVE-.*?-.*?)</).map &.[1]
    match3 = content.scan(/(CVE-.*?-.*?)\\/).map &.[1]

    match_fin = match1 | match2 | match3
    match_size = match_fin.size
    
    if match_size != 0 
        puts "[+] CVE-s found -> #{match_fin}"
    else
        puts "[-] No CVE-s found"
        exit(1)
    end
    x = 0
    loop do
        get_NVD(match_fin[x])
        x+=1
        break if x>=match_size
    end
end

## CUSTOM CVE FROM ARG
if destination !=""
    match1 = destination.scan(/(CVE-.*?-.*?),/).map &.[1]
    match2 = destination.scan(/,(CVE-.*?-.....?)/).map &.[1]
    match_fin = match1 | match2
    puts match_fin
    size = match_fin.size
    x = 0
    loop do
        get_NVD(match_fin[x])
        x=x+1
        break if x>=size
    end
end

   
def get_NVD(dest)
    begin
        HTTP::Client.get "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=#{dest}" do |resp|

            val = JSON.parse(resp.body_io.gets_to_end)
            val = val.to_json
            puts "[+] Current CVE -> #{dest}"
            puts "*" * 50

        #Description
            if reg = /"descriptions":\[{"lang":"en","value":"(.*?)"}/.match(val)
            puts "Description: #{reg[1]}"
            else
            puts "Error finding description!"
            end
        #Date
            if reg = /"published":"(.*?)T/.match(val)
            puts "Published Date (Y/M/D): #{reg[1]}"
            else
            puts "Error finding publish date!"
            end
        #Base Score
            if reg = /"baseScore":(.*?),"baseSeverity":"(.*?)"/.match(val)
                puts "Base Score: #{reg[1]}"
                puts "Base Severity: #{reg[2]}"
            else
                puts "Error finding base score and severity!"
            end
        #Attack Vector & Complexity
            if reg = /"attackVector":"(.*?)","attackComplexity":"(.*?)",/.match(val)
                puts "Attack Vector: #{reg[1]}"
                puts "Attack Complexity #{reg[2]}"
            else
                puts "error finding attack vector and complexity!"
            end
        end 
        puts "*" * 50
    rescue
        puts "[-] THere was an error making the HTTP request"
    end  
end