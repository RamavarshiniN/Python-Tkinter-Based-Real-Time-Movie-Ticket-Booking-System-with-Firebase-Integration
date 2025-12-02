# Python-Tkinter-Based-Real-Time-Movie-Ticket-Booking-System-with-Firebase-Integration
**Project Description :**
The project is titled a Python-Tkinter Based Real-Time Movie Ticket Booking System with Firebase Integration. It is designed as a full-featured, desktop-based movie ticket booking application developed using Python.

**Core Functionality and Architecture :**
The system utilizes the tkinter library to create a dynamic and user-friendly graphical user interface (GUI). It employs a client-server model:
1. Frontend (Client): Tkinter acts as the client, handling user interaction and ticket booking through a graphical interface.
2. Backend (Server): Google’s Firebase Realtime Database is integrated as the backend.
This architecture allows for real-time data synchronization. Data, such as seat availability and pricing, is guaranteed to be always up-to-date across all running instances of the application. The system was developed to provide a secure, interactive platform that addresses inefficiencies in conventional booking systems, specifically by incorporating dynamic pricing, last-minute ticket bidding, and flexible pay-later booking options.
The application ensures live synchronization by performing all backend logic (booking management, seat allocation, logging) via direct calls to Firebase APIs from the Python codebase.
Technology Stack Used
The system leverages the following key technologies:
• Frontend: Python Tkinter GUI.
• Backend: Firebase Realtime Database for storing data.
• Security: Password hashing using bcrypt.
• Core Libraries: Python’s datetime, uuid, regex, and os modules.

![WhatsApp Image 2025-12-01 at 10 46 16 PM](https://github.com/user-attachments/assets/f9d48c48-dd56-499f-b40e-d3d70ca77253)

**Key Features :**
The system is built around several core and advanced features designed to enhance security, efficiency, and user experience.
**1. Security and Authentication**
• Robust Authentication: Only verified users and admins can access the application.
• Password Encryption (Bcrypt): All passwords undergo bcrypt hashing with robust salting before storage in Firebase. The login process checks the stored bcrypt hash using comparison functions.
• Input Validation: Robust input validation using regular expressions and programmatic checks is central to registration and login. This validation minimizes errors, enforces password complexity rules, and ensures username uniqueness.
**2. Real-Time and Concurrency Management
**• Real-time Seat Availability: Provides a constantly updated visualization of seat availability. The GUI uses a color-coded layout where statuses (booked, reserved, available) are distinguishable, such as red for booked, orange for reserved, and green for available.
• Atomic Transactions: Performance and data consistency during highly concurrent seat bookings are ensured by Firebase’s transactional update mechanism. High-conflict operations are wrapped in atomic transactions to prevent race conditions and double allocations.
• Data Synchronization: Any change committed to the backend is instantly available in real time to every connected client.
**3. Booking and Allocation Features
**• Ticket Booking System: Verifies user credentials, seat selection, and payment status. It uses adaptive validation rules to eliminate duplicates and prevent overbooking.
• Dynamic Pricing Algorithm: Ticket prices are not static; they evolve based on current seat occupancy. The price scales using the formula: New Price = Base Price × (1 + 0.005 × Occupancy Percentage).
• Payment Flexibility: Supports both ‘Pay Now’ (instant confirmation) and ‘Pay Later’ (reservation with a deadline) models.
• Deadline Management for Reserved Seats: Each ‘Pay Later’ booking has a clear expiry time. Built-in background jobs (using Tkinter’s scheduling) periodically check for and automatically cancel expired reservations, releasing unclaimed seats back into the pool.
• Seat Bidding System: Canceled seats enter a bidding pool where users can bid. The system enforces a minimum bid increment and awards the seat to the highest bidder after a designated timeout period.
**4. Administrative and Auditing Features
**• Admin Management Panel: Administrative users access a dedicated dashboard to manage shows (add/remove), view all user bookings, resolve bid battles, and monitor real-time transaction history.
• Movie Show Management: Admins can create and delete movie shows, with advanced validation blocking the addition of past events.
• Automatic Show Cleanup: Regularly scheduled routines delete outdated movies and related bookings to prevent database bloat.
• Transaction Logging: Every significant action (booking, payment, cancellation, bid placement) is recorded as a unique transaction with details such as timestamp, seats, and payment status, providing a comprehensive audit trail.
**5. GUI Implementation
**• Custom Widget Classes: The application uses custom classes like NeonButton (neon-effect action buttons with dynamic hover states) and ValidatingEntry (highlights valid or invalid input actively) to provide immediate feedback and enhance usability.
• Event Handling: Tkinter’s event system is used for both direct user actions and scheduled background tasks (like checking pay-later deadlines)
