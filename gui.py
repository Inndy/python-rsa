from tk import *
from rsa import *
from utils import *
import sys

sys.path.insert(0, './pygubu')
import pygubu

class App(object):
    def __init__(self, master):
        self.builder = builder = pygubu.Builder()
        builder.add_from_file('main.ui')
        self.mainwindow = builder.get_object('Frame_1', master)

        self.keysize = builder.get_object('spnKeysize')
        self.keystatus = builder.get_object('txtKeystatus')
        self.datatxt = builder.get_object('txtData')

        self.setkey(RSAKey(bits=768))

        builder.connect_callbacks({
            k: getattr(self, k) for k in dir(self) if k[0] != '_'
        })

    def setkey(self, key):
        self.key = key
        self.rsa = RSA(key)
        self.dumpkey(key)

    def dumpkey(self, key):
        def f(v):
            if v == None:
                return 'None'
            elif type(v) in IntTypes:
                return '0x%x' % v
            else:
                return repr(v)
        r = [ '%s = %s' % (k, f(getattr(key, k, None))) for k in RSAKey.KEYS]
        self.keystatus.delete("@0,0", 'end')
        self.keystatus.insert("@0,0", '\n'.join(r))

    def keygen(self):
        try:
            sz = int(self.keysize.get())
        except ValueError:
            messagebox.showwarning('Input Error', 'Not a number')

        if sz not in range(512, 8193):
            messagebox.showwarning('Out of bound', 'Key size must between [512, 8192]')
            return

        self.setkey(RSAKey(bits=sz))

    def savekey(self):
        try:
            with filedialog.asksaveasfile('w') as fout:
                fout.write(self.key.to_json())
                messagebox.showinfo('File Saved', 'File saved to %s' % fout.name)
        except:
            messagebox.showwarning('Failed Saving Error', 'Can not save file')

    def loadkey(self):
        try:
            with filedialog.askopenfile('r') as fin:
                self.setkey(RSAKey.from_json(fin.read()))
                messagebox.showinfo('Key Loaded', 'RSA Keypair loaded from %s' % fin.name)
        except:
            messagebox.showwarning('File Loading Error', 'Can not load file')

    @property
    def data(self):
        return self.datatxt.get('@0,0', 'end')[:-1]

    @data.setter
    def data(self, value):
        self.datatxt.delete("@0,0", 'end')
        self.datatxt.insert("@0,0", value)

    @property
    def hexdata(self):
        try:
            return unhex(self.data.replace(' ', ''))
        except:
            return None

    def enchex(self):
        data = self.hexdata
        if not data:
            messagebox.showwarning('Error data format', 'Input data is not hex encoded')
            return
        self.data = ensure_str(enhex(self.rsa.encrypt_data(data)))

    def enctxt(self):
        self.data = ensure_str(enhex(self.rsa.encrypt_data(ensure_bytes(self.data))))

    def dechex(self):
        data = self.hexdata
        if not data:
            messagebox.showwarning('Error data format', 'Input data is not hex encoded')
            return
        self.data = ensure_str(enhex(self.rsa.decrypt_data(data)))

    def dectxt(self):
        data = self.hexdata
        if not data:
            messagebox.showwarning('Error data format', 'Input data is not hex encoded')
            return
        self.data = ensure_str(self.rsa.decrypt_data(data))

if __name__ == '__main__':
    root = tkinter.Tk()
    root.title('RSA Tool')
    app = App(root)
    root.mainloop()
