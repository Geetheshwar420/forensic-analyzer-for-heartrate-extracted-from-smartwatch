import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Listbox, Scrollbar, END, MULTIPLE
import matplotlib.pyplot as plt
from threading import Thread
import queue

class ForensicDataTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Data Extraction Tool")
        self.root.geometry("600x600")  # Set window size

        # Queue for managing thread results
        self.result_queue = queue.Queue()

        # Create main frame
        self.main_frame = tk.Frame(self.root, padx=20, pady=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Buttons Frame
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        # Create buttons
        self.browse_button = tk.Button(self.button_frame, text="Browse Local Files", 
                                       command=self.load_files_threaded, width=20)
        self.browse_button.pack(pady=5)

        self.exit_button = tk.Button(self.button_frame, text="Exit", 
                                     command=self.root.quit, width=20)
        self.exit_button.pack(pady=5)

        # Status Frame
        self.status_frame = tk.LabelFrame(self.main_frame, text="Status", padx=10, pady=10)
        self.status_frame.pack(fill=tk.X, pady=10)

        self.status_label = tk.Label(self.status_frame, text="Ready")
        self.status_label.pack()

        # Anomalies Frame
        self.anomalies_frame = tk.LabelFrame(self.main_frame, text="Detected Anomalies", padx=10, pady=10)
        self.anomalies_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.anomalies_frame.pack_forget()  # Hide until anomalies are detected

        self.thread = None  # Thread for background processing
        self.df = None  # DataFrame reference for loaded data
        self.file_path = None  # Store file path for saving changes

    def load_files_threaded(self):
        # Start background loading and processing in a new thread
        self.thread = Thread(target=self.browse_files)
        self.thread.start()
        self.status_label.config(text="Processing files...")
        self.root.after(100, self.check_queue)  # Schedule periodic queue checking

    def check_queue(self):
        try:
            # Check the queue for results
            result = self.result_queue.get_nowait()
            if isinstance(result, str):  # Error message
                self.status_label.config(text="Error loading file")
                messagebox.showerror("Error", result)
            elif isinstance(result, tuple):  # Data and anomalies
                self.df, anomalies, self.file_path = result
                self.status_label.config(text="File(s) loaded and analyzed successfully")
                if not anomalies.empty:
                    self.display_anomalies(anomalies)
                else:
                    messagebox.showinfo("No Anomalies", 
                                        "No significant anomalies detected in the loaded data.")
        except queue.Empty:
            # Keep checking if the thread is still alive
            if self.thread.is_alive():
                self.root.after(100, self.check_queue)
            else:
                self.status_label.config(text="File processing completed")

    def browse_files(self):
        try:
            file_paths = filedialog.askopenfilenames(filetypes=[("CSV files", "*.csv")])
            for file_path in file_paths:
                if file_path:
                    # Efficiently read only necessary columns
                    self.df = pd.read_csv(file_path, usecols=['timestamp', 'heart_rate'])
                    self.df = self.clean_data(self.df)
                    anomalies = self.analyze_data(self.df)
                    
                    # Put result in the queue for the main thread to handle
                    self.result_queue.put((self.df, anomalies, file_path))

        except Exception as e:
            self.result_queue.put(str(e))  # Send error to the main thread

    def clean_data(self, df):
        # Drop rows with missing values in an optimized manner
        return df.dropna(subset=['timestamp', 'heart_rate'])

    def plot_heart_rate(self, df):
        plt.figure(figsize=(10, 5))
        plt.plot(df['timestamp'], df['heart_rate'], label="Heart Rate")
        plt.xlabel('Time')
        plt.ylabel('Heart Rate')
        plt.title('Heart Rate Over Time')
        plt.grid(True)
        plt.legend()
        plt.show()

    def analyze_data(self, df):
        # Efficient anomaly detection using vectorized operations
        mean_hr = df['heart_rate'].mean()
        std_hr = df['heart_rate'].std()
        
        # Identify anomalies using vectorized condition
        anomalies = df[(df['heart_rate'] < mean_hr - 2 * std_hr) | 
                       (df['heart_rate'] > mean_hr + 2 * std_hr)]
        
        return anomalies  # Return anomalies for further processing in browse_files

    def display_anomalies(self, anomalies):
        # Make the anomalies frame visible
        self.anomalies_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        for widget in self.anomalies_frame.winfo_children():
            widget.destroy()  # Clear any previous anomalies display

        tk.Label(self.anomalies_frame, text="Select timestamps to modify or remove:").pack(pady=5)
        self.listbox = Listbox(self.anomalies_frame, selectmode=MULTIPLE, width=50, height=15)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Populate listbox in bulk operation for speed
        self.anomaly_data = anomalies  # Store anomalies for easy reference
        for index, row in anomalies.iterrows():
            self.listbox.insert(END, f"{index} - {row['timestamp']} (HR: {int(row['heart_rate'])})")

        # Scrollbar for the Listbox
        scrollbar = Scrollbar(self.listbox, orient="vertical")
        scrollbar.config(command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")

        # Add buttons
        modify_button = tk.Button(self.anomalies_frame, text="Modify Selected", command=self.modify_selected_anomalies)
        modify_button.pack(pady=5)
        
        remove_button = tk.Button(self.anomalies_frame, text="Remove Selected", command=self.remove_selected_anomalies)
        remove_button.pack(pady=5)

    def modify_selected_anomalies(self):
        selected_indices = self.listbox.curselection()

        if not selected_indices:
            messagebox.showinfo("No Selection", "No anomalies selected for modification.")
            return

        # Process selected anomalies
        for index in selected_indices:
            anomaly_text = self.listbox.get(index)
            row_index = int(anomaly_text.split(" - ")[0])  # Extract the row index
            row = self.df.loc[row_index]

            new_value = simpledialog.askfloat(
                "Modify Anomaly", 
                f"Enter new integer heart rate for timestamp {row['timestamp']}:"
            )
            if new_value is not None:
                self.df.at[row_index, 'heart_rate'] = int(new_value)
                self.listbox.delete(index)  # Update listbox in real-time
                self.listbox.insert(index, f"{row_index} - {row['timestamp']} (HR: {int(new_value)})")

        # Save changes prompt
        self.save_changes()

    def remove_selected_anomalies(self):
        selected_indices = self.listbox.curselection()

        if not selected_indices:
            messagebox.showinfo("No Selection", "No anomalies selected for removal.")
            return

        for index in reversed(selected_indices):  # Reverse to avoid re-indexing issues
            anomaly_text = self.listbox.get(index)
            row_index = int(anomaly_text.split(" - ")[0])  # Extract the row index
            self.df.drop(index=row_index, inplace=True)
            self.listbox.delete(index)  # Remove from listbox

        # Save changes prompt
        self.save_changes()

    def save_changes(self):
        # Save the modified dataframe back to the CSV file with integer formatting
        save_option = messagebox.askyesno("Save Changes", 
                                          "Do you want to save changes to the original file?")
        if save_option:
            self.df['heart_rate'] = self.df['heart_rate'].astype(int)  # Ensure integer format
            self.df.to_csv(self.file_path, index=False)
            messagebox.showinfo("Success", f"Data saved successfully at {self.file_path}")
        else:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Save Modified Data As"
            )
            if save_path:
                self.df['heart_rate'] = self.df['heart_rate'].astype(int)  # Ensure integer format
                self.df.to_csv(save_path, index=False)
                messagebox.showinfo("Success", f"Data saved successfully at {save_path}")

def main():
    root = tk.Tk()
    app = ForensicDataTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()