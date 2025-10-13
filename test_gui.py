import tkinter as tk
from tkinter import ttk

def test_basic_gui():
    """Test if basic Tkinter works"""
    root = tk.Tk()
    root.title("Test Window")
    root.geometry("400x200")
    
    label = ttk.Label(root, text="Tkinter is working! If you see this, the GUI system is functioning.")
    label.pack(pady=20)
    
    button = ttk.Button(root, text="Close", command=root.destroy)
    button.pack(pady=10)
    
    print("GUI test window should appear now...")
    root.mainloop()
    print("GUI test completed.")

if __name__ == "__main__":
    test_basic_gui()