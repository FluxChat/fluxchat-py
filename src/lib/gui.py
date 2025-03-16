from logging import Logger, getLogger
from tkinter import Label, Tk, Entry, Frame, StringVar, Event, Button, Toplevel, Text
from tkinter import X, LEFT, TOP, BOTTOM, SUNKEN, BOTH
from tkinter.ttk import Notebook


class MainFrame(Frame):
	_master: Tk
	_logger: Logger
	_status: Label

	def __init__(self, master: Tk):
		super().__init__(master)
		self._master = master
		# self.pack(pady=400, padx=200)

		self._logger = getLogger('app.gui')
		self._logger.info('GuiFrame init')

		self._status = Label(master, text='Ready', anchor='w', relief=SUNKEN)
		self._status.pack(fill=X, side=BOTTOM, pady=8, padx=5)

		btn1 = Button(master, text='New Message', command=self.on_newmsg_click)
		btn1.place(x=0, y=0)

		tabControl = Notebook(master)
		tab1 = Frame(tabControl)
		tab2 = Frame(tabControl)
		tab3 = Frame(tabControl)

		lbl = Label(tab1, text='Messages')
		lbl.grid(column=0, row=0, padx=30, pady=30)

		lbl = Label(tab2, text='Queue')
		lbl.grid(column=0, row=0, padx=30, pady=30)

		lbl = Label(tab3, text='Nodes')
		lbl.grid(column=0, row=0, padx=30, pady=30)

		tabControl.add(tab1, text ='Messages')
		tabControl.add(tab2, text ='Queue')
		tabControl.add(tab3, text ='Nodes')

		tabControl.pack(fill=BOTH, padx=0, pady=btn1.winfo_reqheight() + 2, expand=1)

	def print_contents(self, event: Event):
		print(type(event))

	def on_newmsg_click(self):
		self._logger.info('on_newmsg_click')
		self._status.config(text='Compose New Message')

		newmsg_win = Toplevel(self._master)
		newmsg_win.resizable(False, False)
		newmsg_win.title('New Message')
		# newmsg_win.geometry('500x300')

		Label(newmsg_win, text='Target:').grid(row=0, column=0, sticky='w', padx=10, pady=5)
		target_entry = Entry(newmsg_win, width=40)
		target_entry.grid(row=0, column=1, padx=10, pady=5)

		Label(newmsg_win, text='Subject:').grid(row=1, column=0, sticky='w', padx=10, pady=5)
		subject_entry = Entry(newmsg_win, width=40)
		subject_entry.grid(row=1, column=1, padx=10, pady=5)

		Label(newmsg_win, text='Message:').grid(row=2, column=0, sticky='w', padx=10, pady=5)
		message_text = Text(newmsg_win, width=40, height=10)
		message_text.grid(row=2, column=1, padx=10, pady=5)

		def send_mesage():
			target_entry.master.destroy()
			self._status.config(text='Sending Message...')

		# Send Button
		send_button = Button(newmsg_win, text='Send', command=send_mesage)
		send_button.grid(row=3, column=1, pady=10)

		newmsg_win.update_idletasks()
		newmsg_win.wm_minsize(newmsg_win.winfo_reqwidth(), newmsg_win.winfo_reqheight())


	def on_messages_click(self):
		self._logger.info('on_messages_click')
