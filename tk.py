from utils import *

if pyversion == 2:
    import Tkinter as tkinter
    import tkMessageBox as messagebox
    import tkFileDialog as filedialog
elif pyversion == 3:
    import tkinter
    import tkinter.messagebox as messagebox
    import tkinter.filedialog as filedialog
else:
    raise Exception('Unsupported python version')
