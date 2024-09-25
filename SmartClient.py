# ALEX GARRETT V00994221
# CSC 361 Assignment 1, 29-9-2023

from socket import *
import ssl, sys, re, signal


def getCookies(headers):
    '''
    DESCRIPTION:

    Extracts cookies from headers
    In particular:
     - name
     - domain
     - expiration
    '''

    cookies = []
    cook = []
    for header in headers:
        if header.lower().startswith('set-cookie:'):
            cookie = []
            cookies = header[len('Set-Cookie: '):].split(';')
            name = cookies[0].split('=')[0]
            cookie.append('cookie name: ' + name)

            for item in cookies[1:]:
                if 'expires=' in item.lower():
                    expires = item[len(' expires='):]
                    cookie.append('expires time: ' + expires)

                elif 'domain=' in item.lower():
                    domain = item[len(' domain='):]
                    cookie.append('domain name: ' + domain)
            cook.append(cookie)

    return cook

def checkH2(host):
    ''' Check if website supports http2 '''
    
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1', 'h2'])
    conn = context.wrap_socket(socket(AF_INET), server_hostname=host)
    try:
        conn.connect((host, 443))
    except:
        return [''], None, None, None, ['']
    h2 = conn.selected_alpn_protocol()
    if h2 == 'h2':
        h2 = 'yes'
    else:
        h2 = 'no'
    conn.close()

    return h2

def handler(signum, frame):
    raise TimeoutError()

def connect(host: str, s, cookies: list):
    '''
    DESCRIPTION:

    Connects to given host
    By default tries port 80, if redirect is encountered, ssl is used on port 443.
    For every response if cookies are detected they are stored
    '''

    reqStr(host, s)
    path = None
    password = 'no'

    # Check for specific page in host URI
    if '/' in host:
        pos = host.find('/')
        path = host[pos:]
        host = host[:pos]

    h2 = checkH2(host)
    # Use ssl to connect on port 443
    if s == True:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket(AF_INET), server_hostname=host)
        conn.connect((host, 443))

    # Use normal socket on port 80 on the first try
    else:
        conn = socket(AF_INET,SOCK_STREAM)
        conn.connect((host, 80))

    # Send request
    host_header = f"Host: {host}\r\n"
    #user = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
    if path == None:
        path = '/'
    print('Checking page', host+path)
    print()
    get = f"GET {path} HTTP/1.1\r\n"
    print(get)

    requestStr = get.encode() + host_header.encode() + b"Connection: Keep-Alive\r\n\r\n"# + user.encode()
    conn.send(requestStr)

    response = conn.recv(1024*2).decode('utf-8')

    # Extract headers and body
    try:
        headers, body = response.split('\r\n\r\n', 1)
    except:
        headers = response
        body = 'No body found\n'

    headers = headers.split('\r\n')
    conn.close()

    # Tries to get cookies at every recursive call
    try:
        cooks = getCookies(headers)
        for cook in cooks:
            cookies.append(cook)
    except:
        pass
    
    # print headers, body, http2, cookies, and password check
    recStr(headers, body)

    # Checks for redirects
    if '400' in headers[0] or '302' in headers[0] or '301' in headers[0]:
        for header in headers:
            if 'location' not in header.lower():
                continue
            
            if 'http' in header:
                host = header[len('Location: '):]
                host = re.search(r'https?://(.+)', host)
                host = host.group(1)

            else:
                h = header[len('Location: '):]
                host = host + h

            print('New page:', host)
            print()
        # recursive call
        headers,body,h2, cookies, password = connect(host, True, cookies)

    # Checks if password protected
    if "401" in headers[0] or '403' in headers[0]:
        password = 'yes'
    
    return headers, body, h2, cookies, password

def reqStr(host, s):
    '''
    Function for output
    '''
    print()
    print('---Request begin---')
    print(f'GET http://{host} HTTP/1.1')
    print('Host:', host)
    print('Connection: Keep-Alive')
    print('ssl:', s)
    print('--Request end--')
    print()

def recStr(headers, body):
    '''
    prints:
     - response header
     - response body
    '''

    print()
    print("---Response header ---")
    for header in headers:
        print(header)
    print()
    print("--- Response body ---")
    print(body)
    print()

def outStr(host, h2, cookies, password):
    '''
    Function for output
    prints:
     - response header
     - http2 support boolean
     - a list of cookies with name, domain, exipiration for each cookie 
     - password protected boolean
    '''

    print('website:', host)
    print('1. Supports http2:', h2)
    print('2. List of Cookies:')
    if cookies != []:
        for cook in cookies:
            print(', '.join(cook))

    print('3. Password-protected:', password)

def main():
    if len(sys.argv)<2:
        print('ERROR: Missing stdin argument; try "python3 SmartClient.py {your website}')
        return
    else:
        host = sys.argv[1]

    cookies = []
    headers, body, h2, cookies, password = connect(host, False, cookies)
    outStr(host, h2, cookies, password)
    
    

if __name__ == "__main__":
    main()

                
            
            


