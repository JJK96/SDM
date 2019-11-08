import npyscreen
from client import *

class Tui(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", MethodSelection, name="SDM Client interface")
        self.addForm("SEARCH", SearchForm, name="SDM Client interface")
        self.addForm("UPLOAD", UploadForm, name="SDM Client interface")

class MethodSelection(npyscreen.ActionForm):
    def create(self):
        self.action = self.add(npyscreen.TitleSelectOne, values=["Search for files","Upload file"], name="What would you like to do?")

    def on_ok(self):
        val = self.action.value[0]
        if val == 0:
            self.parentApp.setNextForm("SEARCH")
        else:
            self.parentApp.setNextForm("UPLOAD")

class InputBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit

class SearchForm(npyscreen.ActionForm):
    def create(self):
        y, x = self.useable_space()
        self.add(npyscreen.BoxTitle, name="Search instructions", values=["To search for files please enter one keyword", "per line. These keywords will be used to search", "for files in the database"], rely=y // 4, max_width=x // 2 - 5, max_height=y // 2, editable=False)
        self.keywordBox = self.add(InputBox, name="Which keywords would you like to search for?", relx=x // 2, rely=2, max_width=x // 2 - 5)

    def on_ok(self):
       keywords = self.keywordBox.value
       self.parentApp.setNextForm(None)

class UploadForm(npyscreen.ActionForm):
    def create(self):
        self.fileName = self.add(npyscreen.TitleFilenameCombo, name="Select file to upload:")
    
    def on_ok(self):
        print(self.fileName.value)
        self.parentApp.setNextForm(None)


App = Tui()
App.run()
