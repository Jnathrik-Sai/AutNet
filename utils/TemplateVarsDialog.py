# utils/dialogs.py or similar
from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QDialogButtonBox, QLineEdit, QVBoxLayout
)

class TemplateVarsDialog(QDialog):
    def __init__(self, variables, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Template Variables")
        self.variables = variables
        self.values = {}

        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        self.inputs = {}

        for var in self.variables:
            line_edit = QLineEdit()
            self.inputs[var] = line_edit
            form_layout.addRow(f"{var}:", line_edit)

        layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self):
        if self.exec_() == QDialog.Accepted:
            return {var: inp.text() for var, inp in self.inputs.items()}
        return None