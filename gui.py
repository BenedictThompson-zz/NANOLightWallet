#TODO
#Previous - could reduce server involvement by storing previous hash, requesting server on boot + updating with each transaction
#Convert PoW to cpython or even a c binary that could be dropped in to increase speed (would also benefit from multicore support)
#Increase timeout on server
datas=[('C:\\Python27\\tcl\\tcl8.5', 'lib\\tcl8.5'),
             ('C:\\Python27\\tcl\\tk8.5', 'lib\\tk8.5')]


from pyblake2 import blake2b
import time
import threading
import tkinter
import websocket
import json
import sys, os
from websocket import create_connection
import ssl
import websocket
from tkinter import *
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
from tkinter import ttk
root=Tk()
root.withdraw()

root.minsize(width=600, height=300)
root.wm_iconbitmap('logo.ico')
root.title('XRB Lite Wallet')
def root_destroy():
    root.destroy()
    
def address_to_clipboard(self=1):
    root.clipboard_clear()
    root.clipboard_append(account)

import binascii
import random, getpass
from bitstring import BitArray
from pure25519 import ed25519_oop as ed25519
from simplecrypt import encrypt, decrypt
from configparser import SafeConfigParser
import pyqrcode

default_representative = \
        'xrb_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic'
raw_in_xrb = 1000000000000000000000000000000.0
choices = u'Send,Account History,Display QR Code,,Configure PoW,Configure Rep,Configure Server,,Refresh,Quit'.split(',')
running_pow_gen = False
class StringDialog(simpledialog._QueryString):
    def body(self, master):
        super().body(master)
        self.iconbitmap('logo.ico')

    def ask_string(title, prompt, **kargs):
        d = StringDialog(title, prompt, **kargs)
        return d.result

def xrb_account(address):
    # Given a string containing an XRB address, confirm validity and
    # provide resulting hex address
    if len(address) == 64 and (address[:4] == 'xrb_'):
        # each index = binary value, account_lookup[0] == '1'
        account_map = "13456789abcdefghijkmnopqrstuwxyz"
        account_lookup = {}
        # populate lookup index with prebuilt bitarrays ready to append
        for i in range(32):
            account_lookup[account_map[i]] = BitArray(uint=i,length=5)

        # we want everything after 'xrb_' but before the 8-char checksum
        acrop_key = address[4:-8]
        # extract checksum
        acrop_check = address[-8:]

        # convert base-32 (5-bit) values to byte string by appending each
        # 5-bit value to the bitstring, essentially bitshifting << 5 and
        # then adding the 5-bit value.
        number_l = BitArray()
        for x in range(0, len(acrop_key)):
            number_l.append(account_lookup[acrop_key[x]])
        # reduce from 260 to 256 bit (upper 4 bits are never used as account
        # is a uint256)
        number_l = number_l[4:]

        check_l = BitArray()
        for x in range(0, len(acrop_check)):
            check_l.append(account_lookup[acrop_check[x]])

        # reverse byte order to match hashing format
        check_l.byteswap()
        result = number_l.hex.upper()

        # verify checksum
        h = blake2b(digest_size=5)
        h.update(number_l.bytes)
        if (h.hexdigest() == check_l.hex):
            return result
        else:
            return False
    else:
        return False

def account_xrb(account):
    # Given a string containing a hex address, encode to public address
    # format with checksum
    # each index = binary value, account_lookup['00001'] == '3'
    account_map = "13456789abcdefghijkmnopqrstuwxyz"
    account_lookup = {}
    # populate lookup index for binary string to base-32 string character
    for i in range(32):
        account_lookup[BitArray(uint=i,length=5).bin] = account_map[i]
    # hex string > binary
    account = BitArray(hex=account)

    # get checksum
    h = blake2b(digest_size=5)
    h.update(account.bytes)
    checksum = BitArray(hex=h.hexdigest())

    # encode checksum
    # swap bytes for compatibility with original implementation
    checksum.byteswap()
    encode_check = ''
    for x in range(0,int(len(checksum.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_check += account_lookup[checksum.bin[x*5:x*5+5]]

    # encode account
    encode_account = ''
    while len(account.bin) < 260:
        # pad our binary value so it is 260 bits long before conversion
        # (first value can only be 00000 '1' or 00001 '3')
        account = '0b0' + account
    for x in range(0,int(len(account.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_account += account_lookup[account.bin[x*5:x*5+5]]

    # build final address string
    return 'xrb_'+encode_account+encode_check

def private_public(private):
    return ed25519.SigningKey(private).get_verifying_key().to_bytes()

def seed_account(seed, index):
    # Given an account seed and index #, provide the account private and
    # public keys
    h = blake2b(digest_size=32)

    seed_data = BitArray(hex=seed)
    seed_index = BitArray(int=index,length=32)

    h.update(seed_data.bytes)
    h.update(seed_index.bytes)

    account_key = BitArray(h.digest())
    return account_key.bytes, private_public(account_key.bytes)

def get_pow(hash, type):
    global running_pow_gen
    cached_work = parser.get('wallet', 'cached_pow')
    if cached_work == '' or type == 'open':
        #Generate work for block
        pow_source = parser.get('wallet', 'pow_source')
        if running_pow_gen == True:
            messagebox.showinfo('Generating PoW', 'The wallet is still generating PoW, please wait until it is complete. This should not take long.')
        if pow_source == 'external':
            data = json.dumps({'action' : 'work_generate', 'hash' : hash})
            ws.send(data)
            block_work = json.loads(str(ws.recv()))
            work = block_work['work']
        else:
            
            running_pow_gen = True
            pow_work = pow_generate(hash)
            work = str(pow_work, 'ascii')
            running_pow_gen = False

        return work
            
    else:
        save_config('cached_pow', '')
        return cached_work

def pow_threshold(check):
    if check > b'\xFF\xFF\xFF\xC0\x00\x00\x00\x00': return True
    else: return False

def pow_generate(hash):
    hash_bytes = bytearray.fromhex(hash)
    test = False
    inc = 0
    while test == False:
        inc += 1
        # generate random array of bytes
        random_bytes = bytearray((random.getrandbits(8) for i in range(8)))
        for r in range(0,256):
            # iterate over the last byte of the random bytes
            random_bytes[7] =(random_bytes[7] + r) % 256
            h = blake2b(digest_size=8)
            h.update(random_bytes)
            h.update(hash_bytes)
            final = bytearray(h.digest())
            final.reverse()
            test = pow_threshold(final)
            if test:
                break

    random_bytes.reverse()
    return binascii.hexlify(random_bytes)

def get_balance(account):
    data = json.dumps({'action' : 'account_balance', 'account' : account})
    ws.send(data)

    balance_result =  json.loads(str(ws.recv()))
    #print(balance_result['balance'])

    balance = float(balance_result['balance']) / raw_in_xrb
    return balance

def get_raw_balance(account):
    data = json.dumps({'action' : 'account_balance', 'account' : account})
    ws.send(data)

    balance_result =  json.loads(str(ws.recv()))
    #print(balance_result['balance'])

    balance = int(balance_result['balance'])
    return balance

def get_previous():
    #Get account info
    accounts_list = [account]
    data = json.dumps({'action' : 'accounts_frontiers', 'accounts' : accounts_list})
    ws.send(data)
    result =  ws.recv()
    #print(result)
    account_info = json.loads(str(result))
    previous = account_info['frontiers'][account]

    return previous

def get_pending():
    #Get pending blocks
    data = json.dumps({'action' : 'pending', 'account' : account})
    
    ws.send(data)
    
    pending_blocks =  ws.recv()
    #print("Received '%s'" % pending_blocks)
    
    rx_data = json.loads(str(pending_blocks))

    return rx_data['blocks']

def save_config(variable, value):
    cfgfile = open("config.ini",'w')
    parser.set('wallet', variable, value)
    parser.write(cfgfile)
    cfgfile.close()


def send_xrb(dest_address, final_balance):
    previous = get_previous()

    priv_key, pub_key = seed_account(seed,index)

    hex_balance = hex(final_balance)
    hex_final_balance = hex_balance[2:].upper().rjust(32, '0')
    #print(final_balance)

    #print("Starting PoW Generation")
    work = get_pow(previous, 'send')
    #workbytes = pow_generate(previous)
    #work = str(workbytes, 'ascii')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(dest_address)).bytes)
    bh.update(BitArray(hex=hex_final_balance).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')

    finished_block = '{ "type" : "send", "destination" : "%s", "balance" : "%s", "previous" : "%s" , "work" : "%s", "signature" : "%s" }' % (dest_address, hex_final_balance, previous, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()
    #print(block_reply)
    return block_reply

def receive_xrb():
    time.sleep(10)
    pending = get_pending()

    if len(pending) > 0:
        data = json.dumps({'action' : 'account_info', 'account' : account})
        ws.send(data)
        info =  ws.recv()
        if len(info) == 37:
            #print('Not found')
            open_xrb()
        else:
            source = pending[0]

            #Get account info
            previous = get_previous()

            priv_key, pub_key = seed_account(seed,index)

            #print("Starting PoW Generation")
            work = get_pow(previous, 'receive')
            #print("Completed PoW Generation")

            #Calculate signature
            bh = blake2b(digest_size=32)
            bh.update(BitArray(hex=previous).bytes)
            bh.update(BitArray(hex=source).bytes)

            sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
            signature = str(binascii.hexlify(sig), 'ascii')
            finished_block = '{ "type" : "receive", "source" : "%s", "previous" : "%s" , "work" : "%s", "signature" : "%s" }' % (source, previous, work, signature)

            data = json.dumps({'action' : 'process', 'block' : finished_block})
            #print(data)
            ws.send(data)

            block_reply = ws.recv()
            save_config('balance', str(get_balance(account)))
            #print(block_reply)
    else:
        if parser.get('wallet', 'cached_pow') == '' and parser.get('wallet', 'open') == '1':
            previous = get_previous()
            work = get_pow(previous, 'cache')
            save_config('cached_pow', work)
    time.sleep(50)

def open_xrb():
    representative = parser.get('wallet', 'representative')
    #Get pending blocks
    data = json.dumps({'action' : 'pending', 'account' : account})

    ws.send(data)

    pending_blocks =  ws.recv()
    #print("Received '%s'" % pending_blocks)

    rx_data = json.loads(str(pending_blocks))
    #for blocks in rx_data['blocks']:
    #print(rx_data['blocks'][0])
    source = rx_data['blocks'][0]

    priv_key, pub_key = seed_account(seed,index)
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    #print("Starting PoW Generation")
    work = get_pow(str(public_key, 'ascii'), 'open')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=source).bytes)
    bh.update(BitArray(hex=xrb_account(representative)).bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')
    finished_block = '{ "type" : "open", "source" : "%s", "representative" : "%s" , "account" : "%s", "work" : "%s", "signature" : "%s" }' % (source, representative, account, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()

    save_config('open', '1')
    #print(block_reply)

def change_xrb():
    representative = parser.get('wallet', 'representative')
    previous = get_previous()

    priv_key, pub_key = seed_account(seed,index)
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    #print("Starting PoW Generation")
    work = get_pow(previous, 'change')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(representative)).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')
    finished_block = '{ "type" : "change", "previous" : "%s", "representative" : "%s" , "work" : "%s", "signature" : "%s" }' % (previous, representative, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()
#print(block_reply)

def item_chosen(choice):

    if choice == 'Refresh':
        global saved_balance
        save_config('balance', str(get_balance(account)))
        saved_balance = str(get_balance(account))
        balance_text.set(('Balance: {} Mxrb').format(int(float(saved_balance))))
        root.update_idletasks()

    elif choice == 'Send':
        global top
        top = Toplevel()
        var = IntVar()
        top.grab_set()
        top.wm_iconbitmap('logo.ico')
        top.title('Send')
        addr = Label(top, text="Destination Address").grid(row=0)
        amount = Label(top, text="Amount in Mxrb").grid(row=1)
        e1 = Entry(top,width=80)
        e2 = Entry(top,width=80)
        e1.grid(row=0, column=1)
        e2.grid(row=1, column=1)
        save=Button(top, text="Send", command=lambda: confirm_send(e1.get(), e2.get()),width=5,pady=5).grid(row=2, column=0)
        back=Button(top, text="Back", command=lambda: top.destroy(),width=5,pady=5).grid(row=2, column=1)
        top.mainloop()


    elif choice == 'Configure PoW':
        pow_source = parser.get('wallet', 'pow_source')
        top = Toplevel()
        var = IntVar()
        top.grab_set()
        top.wm_iconbitmap('logo.ico')
        top.title('Configure PoW Source')
        rb1 = Radiobutton(top, text = 'Internal PoW', variable = var,value = 1)
        rb2 =Radiobutton(top, text = 'External PoW', variable = var,value = 2)
        save=Button(top, text="Save", command=lambda: change_pow(var.get()),width=5,pady=5)
        back=Button(top, text="Back", command=lambda: top.destroy(),width=5,pady=5)
        if pow_source == 'internal':
            var.set(1)
        elif pow_source == 'external':
            var.set(2)
        rb1.pack()
        rb2.pack()
        save.pack()
        back.pack()
        top.mainloop()
    elif choice == 'Configure Rep':
        representative = parser.get('wallet', 'representative')
        xrb_rep = simpledialog.askstring('Configure Representative', 'Representative:', initialvalue=representative)
        if xrb_rep != None:
            update_rep(xrb_rep)


    elif choice == 'Configure Server':
        node_server = parser.get('wallet', 'server')
        xrb_server = simpledialog.askstring('Configure Server', 'Server:', initialvalue=node_server)
        if xrb_server != None:
            update_server(xrb_server)

    elif choice == 'Display QR Code':
        data = 'xrb:' + account
        xrb_qr = pyqrcode.create(data, error='L', version=4, mode=None, encoding='iso-8859-1')
        xrb_qr_xbm = xrb_qr.xbm(scale=10)
        top = Toplevel()
        top.grab_set()
        code_bmp = BitmapImage(data=xrb_qr_xbm)
        code_bmp.config(background="white")
        label = Label(top,image=code_bmp)
        label.pack()
        back=Button(top, text="Back", command=lambda: top.destroy(),width=5,pady=5)
        back.pack()
        top.mainloop()

    elif choice == 'Account History':
        data = json.dumps({ "action": "account_block_count", "account": account })
        ws.send(data)
        block_count =  ws.recv()
        rx_data = json.loads(str(block_count))
        if 'error' in rx_data:
            account_block_count = '0'
            history_title = 'Account History (' + account_block_count + ')'
            top = Toplevel()
            top.title(history_title)
            master = tkinter.Frame(top)
            master.pack()
            tree = ttk.Treeview(master, columns=['Transaction Type','Account','Amount'])
            tree.heading('Transaction Type', text='Transaction Type')
            tree.heading('Account', text='Account')
            tree.heading('Amount', text='Amount')
            tree.pack()
        else:
            account_block_count = rx_data['block_count']
            data = json.dumps({'action' : 'account_history', 'account' : account, 'count': int(account_block_count)})
            ws.send(data)
            history_blocks =  ws.recv()
            rx_data = json.loads(str(history_blocks))
            
            history_title = 'Account History (' + account_block_count + ')'
            top = Toplevel()
            top.title(history_title)
            master = tkinter.Frame(top)
            master.pack()
            tree = ttk.Treeview(master, columns=['Transaction Type','Account','Amount'])
            tree.heading('Transaction Type', text='Transaction Type')
            tree.heading('Account', text='Account')
            tree.heading('Amount', text='Amount')
            tree.pack()
            rx_data['history'].reverse()
            tree['show'] = 'headings'
            for i in range (len(rx_data['history'])):
                tree.insert("",index=0,text=str(len(rx_data['history'])-i),values=[rx_data['history'][i]['type'],rx_data['history'][i]['account'],(float(rx_data['history'][i]['amount'])/10**30)])
            
            
            

def update_rep(xrb_rep):
    new_rep = xrb_rep
    if len(new_rep) != 64 or new_rep[:4] != "xrb_":
        messagebox.showerror('Error', 'That is not a valid RaiBlocks address.')
    else:
        save_config('representative', new_rep)
        #Send change block
        change_xrb()

def update_server(xrb_server):
    save_config('server', xrb_server)
    ws.close()
    simpledialog.messagebox.showinfo('Restart', 'The program requires a restart.')
    root.destroy()

def restart():
    """Restarts the current program.
    Note: this function does not return. Any cleanup action (like
    saving data) must be done before calling this function."""
    python = sys.executable
    os.execl(python, python, * sys.argv)


def change_pow(response):
    if response == 1:
        save_config('pow_source', 'internal')
        pow_source = 'internal'
    elif response == 2:
        save_config('pow_source', 'external')
        pow_source = 'external'
    top.destroy()


def confirm_send(final_address, xrb_amount):
    #Lets check the details here
    #Calculate amount to send
    #send_amount is in Mxrb,
    send_amount = xrb_amount
    send_address = final_address
    rai_send = float(send_amount) * 1000000 #float of total send
    raw_send = str(int(rai_send)) + '000000000000000000000000'
    #Create the new balance
    int_balance = int(get_raw_balance(account))
    new_balance = int_balance - int(raw_send)
    #print(new_balance)

    if len(send_address) != 64 or send_address[:4] != "xrb_":
        messagebox.showerror('Error', 'Invalid Address')
        top.destroy()
    elif type(xrb_amount) is int: 
        if not xrb_amount <= int_balance:
            messagebox.showerror('Error', 'Invalid Amount')
            top.destroy()


    else:
        if messagebox.askyesno('Sending', ('Dest: {}\n Amount: {} Mxrb\n New Balance: {} Mxrb\n Are You Sure?').format(send_address,send_amount,new_balance)) == True:
            process_send(send_address, int(rai_send))


def process_send(final_address, final_balance):
    outcome = send_xrb(str(final_address), final_balance)
    if len(outcome) == 4:
        messagebox.showinfo('Sent', 'Transaction Successfully Sent')
        save_config('balance', str(get_balance(account)))
        top.destroy()
    else:
       messagebox.showerror('Failed', 'Transaction Failed')
       top.destroy()

class StringDialog(simpledialog._QueryString):
    def body(self, master):
        super().body(master)
        self.iconbitmap('logo.ico')

def ask_string(title, prompt, **kargs):
    d = StringDialog(title, prompt, **kargs)
    return d.result

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        ciphertext = encrypt(password, plaintext)
        output.write(ciphertext)

parser = SafeConfigParser()
config_files = parser.read('config.ini')


while True:
    password = ask_string("Password", "Enter password:", show='*')
    password_confirm = ask_string("Password", "Confirm password:", show='*')
    if password == None or password == '':
        sys.exit()
    if password == password_confirm:
        break
    
    messagebox.showerror('Error', 'Password Mismatch')


if len(config_files) == 0:
    full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
    wallet_seed = full_wallet_seed[2:].upper()
    write_encrypted(password, 'seed.txt', wallet_seed)

    cfgfile = open("config.ini",'w')
    parser.add_section('wallet')
    priv_key, pub_key = seed_account(str(wallet_seed), 0)
    public_key = str(binascii.hexlify(pub_key), 'ascii')

    account = account_xrb(str(public_key))
    with open('data.txt', 'w') as f:
        f.write(('Wallet Seed: {}\nPublic Key: {}\nAccount Address: {}\n').format(wallet_seed, public_key, account))
        f.write('\nStore the data in a safe place (for example on paper) and DELETE THIS FILE!')
        f.close()
    messagebox.showinfo('Info','Seed and Address written to "data.txt", ensure that you store your data in a safe place and delete this file.')
    parser.set('wallet', 'account', account)
    parser.set('wallet', 'index', '0')
    parser.set('wallet', 'representative', default_representative)
    parser.set('wallet', 'pow_source', 'external')
    parser.set('wallet', 'server', 'wss://yapraiwallet.space')
    parser.set('wallet', 'cached_pow', '')
    parser.set('wallet', 'balance', '0')
    parser.set('wallet', 'open', '0')

    parser.write(cfgfile)
    cfgfile.close()
    index = 0
    seed = wallet_seed
else:
    try:
        seed = read_encrypted(password, 'seed.txt', string=True)
    except:
        messagebox.showerror('Error', 'Error decoding seed, check password and try again')
        sys.exit()

account = parser.get('wallet', 'account')
index = int(parser.get('wallet', 'index'))
representative = parser.get('wallet', 'representative')
pow_source = parser.get('wallet', 'pow_source')
node_server = parser.get('wallet', 'server')
cached_work = parser.get('wallet', 'cached_pow')
saved_balance =float(parser.get('wallet', 'balance'))
account_open = parser.get('wallet', 'open')

try:
    ws = create_connection(node_server)
except Exception as e:
    print (e)
    messagebox.showerror('Error', ' Failed to connect to backend server\nTry again later or change the server in config.ini')
    sys.exit()


thread = threading.Thread(target=receive_xrb)
thread.start()
root.deiconify()
balance_text = StringVar()
balance_text.set(('Balance: {} Mxrb').format(int(float(saved_balance))))
l_title = Label(root, text="RetroXRBWallet")
l_address = Text(root,height=1, width=65)
l_address.insert(1.0, account)
l_address.bind('<Double-Button-1>',address_to_clipboard)
l_balance = Label(root, textvariable=balance_text)
l_title.pack()
l_address.pack()
l_balance.pack()

b_send=Button(root, text="Send", command=lambda:item_chosen('Send'),width=25,pady=7)
b_history=Button(root, text="Account History", command=lambda:item_chosen('Account History'),width=25,pady=7)
b_qr=Button(root, text="Display QR Code", command=lambda:item_chosen('Display QR Code'),width=25,pady=7)
b_pow=Button(root, text="Configure PoW", command=lambda:item_chosen('Configure PoW'),width=25,pady=7)
b_rep=Button(root, text="Configure Rep", command=lambda:item_chosen('Configure Rep'),width=25,pady=7)
b_server=Button(root, text="Configure Server", command=lambda:item_chosen('Configure Server'),width=25,pady=7)
b_refresh=Button(root, text="Refresh", command=lambda:item_chosen('Refresh'),width=25,pady=7)
b_quit=Button(root, text="Quit", command=root_destroy,width=25,pady=7)




for c in sorted(root.children):
    root.children[c].pack()

l_address.configure(state="disabled",exportselection=1)

root.mainloop()

