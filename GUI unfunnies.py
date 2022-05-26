#GUI unfunnies v0.3
from tkinter import *
from tkinter import ttk
from PIL import Image, ImageTk
import winsound
from HSCpwgenfuncs import *

#Initiate window
#window = Tk()
#FirstTimeScreen()

class App_Window(Tk):
    def __init__(self):                                                 #funny set up initial window attributes for whole program
        Tk.__init__(self)                                               #Initialise Tk?
        self.title('brother')
        self.geometry("720x1280")
    
        #self.iconbitmap("OIP.ico")
        main_window_frame = Frame(self)# Define and make a frame object in this window object
        main_window_frame.pack()#Pack the frame to be visible in the window

        self.frames = {}
        for f in {FirstTimeScreen}: 
            frame = f(main_window_frame, self) #creating instances and referencing where they are stored. frame = f{parent, container}
            self.frames[f] = frame
            frame.pack() #sticky makes frames stick to each side to you don't see what's behind when changing
        self.showframes(FirstTimeScreen)
        
        #make method showFrames
    def showframes(self, container):
        frame = self.frames[container]  # specifies which frame we want
        frame.tkraise() #brings it to the front
        # frame = Main(main_window_frame, self)
        # frame.grid(row=0,column=0, sticky='nsew')
        # Main.tkraise(self)

class FirstTimeScreen(Frame):
    def __init__(self,parent,container):
        # for widget in container.winfo_children():
        #     widget.destroy()
        Frame.__init__(self,parent)#Makes a Tk GUI window object as a part of this object
        #self.geometry('1280x720')
        #main_window_frame = Frame(self)# Define and make a frame object in this window object
        #main_window_frame.pack()#Pack the frame to be visible in the window
        lbl = Label(self, text="Choose a Master Password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(self, width=20, show="*")
        txt.pack()
        txt.focus()

        lbl1 = Label(self, text="Re-enter password")
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        txt1 = Entry(self, width=20, show="*")
        txt1.pack()

        btn = Button(self, text="Save")
        btn.pack(pady=5)

        self.poptext = StringVar()
        self.poptext.set('f')
        testolab = Label(self, textvariable=self.poptext)
        testolab.pack(pady=10)
        def bruh(self,txt2):
            txt2.set(txt2.get()+ ';')
            #bbren = txt + ';'
            #bbren +=';'
            #self.poptext.set(bbren)
            print(self.poptext.get())
            testolab.config(text=self.poptext)

        stev = Image.open("funnyresources/SteveMinecraft.png")
        stev = stev.resize((120, 120))
        stev = ImageTk.PhotoImage(stev)
        stev.image = stev
        ponger = Button(self, image=stev, command=lambda: bruh(self,self.poptext), borderwidth=0)#, height=5, width=5)
        ponger.pack(pady=5, side= TOP)
            
def main():
    passy = App_Window()
    passy.mainloop()

if __name__ == '__main__':
    main()