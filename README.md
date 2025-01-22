# PortScanner
Advanced Port Scanner In Python
 |
 |
`-----------------------------------------------------------------------------------------------------------`
 |
 |                                      **WARNING**
 |                                     
**THIS PROGRAM WAS MADE FOR EDUCATIONAL PURPOSES ONLY, WE ARE NOT RESPONSIBLE FOR ANY MISUSE OR ILLICIT ACTIVITIES**
 |
 |
`-----------------------------------------------------------------------------------------------------------`
 |
 |
***Installation***
```bash
git clone https://github.com/nullsleeps/PortScanner.git
cd PortScanner
python main.py
```
 |
 |
***Steps to Run the Program:***
 |
**How To Use:**
 |
**Input Target Information:**
 |
*Once the GUI opens, enter the target IP address* `(e.g., 192.168.1.1)`.
 |
*Specify the port range by entering the Start Port and End Port fields* `(e.g., 1 to 1024)`.
 |
 |
**Start Scanning:**
 |
*Click the* ***"Start Scan"*** *button to begin scanning the specified ports on the target IP address*.
 |
*The scan results will appear in the output box below, showing which ports are open.*
 |
 |
`-----------------------------------------------------------------------------------------------------------`
 |
 |
***How It Works:***
 |
**Port Scanning Logic:**
 |
*The program uses the* ***socket*** *library to attempt to connect to each port in the specified range on the target IP.*
 |
*If a connection is successful, the port is marked as* `"open."`
 |
*Each port is scanned in a separate thread, significantly speeding up the process.*
 |
 |
**Threading:**
 |
*The threading module ensures that multiple ports are scanned simultaneously.*
 |
*This allows the scanner to handle large port ranges efficiently without freezing the GUI.*
 |
 |
**GUI Integration:**
 |
*Built with* ***tkinter***, *the GUI provides a simple interface to input IP and port ranges.*
 |
*The results are displayed in a text box, making it user-friendly.*
 |
 |
**Error Handling:**
 |
*Invalid inputs, such as an incorrect IP address or invalid port ranges, are handled gracefully with appropriate error messages.*
 |
*Ports that cannot be scanned due to network issues or permissions are logged as errors in the results.*
 |
 |
`-----------------------------------------------------------------------------------------------------------`
 |
 |
***Notes:***
 |
**Performance:**
 |
*Threading enhances speed, but scanning very large port ranges* `(e.g., 1–65535)` *may take time, depending on the network and target system.*
 |
 |
**Ethical Usage:**
 |
***Ensure you have explicit permission to scan the target system.***
 |
***Unauthorized scanning may violate laws and ethical guidelines.***
 |
 |
 |
***And Most Of All, Have Fun :)***
