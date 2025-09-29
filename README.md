# FabraForma AL - Additive Ledger

FabraForma AL is a comprehensive management application designed for 3D printing services and enthusiasts. It provides a full suite of tools to track print jobs, calculate costs, manage resources, and generate customer quotations, all through a user-friendly desktop client connected to a powerful Flask backend.

## Key Features

- **Multi-Tenant System:** Supports multiple companies, each with its own isolated set of users, data, and configurations.
- **User & Company Management:** Full support for company registration, user creation, and role-based access control (admins and users).
- **Secure Authentication:** A robust login system using JWT for token-based authentication, including a "Remember Me" feature for persistent sessions.
- **Resource Management:** Easily manage your inventory of printers and filaments, including detailed specifications like setup costs, maintenance schedules, power consumption, and material prices.
- **Automated Job Processing:**
  - A client-side monitor watches a designated folder for new print summary images.
  - **Optical Character Recognition (OCR)** automatically extracts print details like filament usage, print time, and material type.
  - A user-friendly verification step allows for quick confirmation or correction of the extracted data before logging.
- **Advanced Cost of Goods Sold (COGS) Calculation:** Automatically calculates the precise cost of each print job by factoring in material usage, print time, labor, and detailed printer-specific costs like depreciation, maintenance, and power consumption.
- **Automated Financial Logging:**
  - Generates a detailed, pre-formatted Excel log for each individual print job.
  - Automatically aggregates all print jobs into a monthly master Excel log with summary totals and hyperlinks to individual logs.
- **Powerful Quotation Generation:**
  - A dedicated tool to create and manage professional customer quotations.
  - **Integrated 3D Model Slicing:** Integrates directly with **OrcaSlicer** to automatically slice STL files, calculate precise print metrics, and generate accurate quotes directly from 3D models.
  - Calculates final pricing based on the calculated COGS and a configurable profit margin.
  - Generates professional-looking PDF quotations, complete with your company logo and details.
- **Server File Management:** An admin-only interface to browse, upload, and download files from a shared server directory.
- **Content Safety:** Includes a built-in NSFW filter to prevent inappropriate images from being uploaded as profile pictures or for job processing.

## Project Structure

The repository is organized into two main components:

- `/server`: Contains the Flask backend application, including all API endpoints, business logic, database configuration, and server-side dependencies.
- `/client`: Contains the `ttkbootstrap` (Tkinter) frontend desktop application, including all GUI components, the API client, and client-side dependencies.

## Setup and Installation

### Prerequisites

- Python 3.8 or newer
- (Optional but Recommended) Git for cloning the repository

### 1. Server Setup

First, set up and run the backend server.

1.  **Navigate to the project root directory** (the one containing the `server` and `client` folders).

2.  **Create and activate a virtual environment:**
    - On macOS/Linux:
      ```bash
      python3 -m venv venv
      source venv/bin/activate
      ```
    - On Windows:
      ```bash
      python -m venv venv
      .\venv\Scripts\activate
      ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r server/requirements.txt
    ```
    *Note: This may take some time as it includes downloading machine learning models for OCR and NSFW detection.*

4.  **(Optional) Configure Server Settings:**
    Open `server/server_config.json`. The default settings are generally fine for local use, but you may need to update the paths for the OrcaSlicer integration if you have it installed in a non-default location:
    - `SLICER_EXECUTABLE_PATH`: The full path to your `orca-slicer.exe` (or equivalent).
    - `SLICER_SYSTEM_PROFILE_PATH`: The path to your OrcaSlicer user profiles directory.

5.  **Run the server:**
    From the **project root directory**, run the server as a module:
    ```bash
    python -m server.app
    ```
    The server will start, initialize the database (`server_data.sqlite` in the root directory), and will be ready to accept connections on `http://localhost:5000`.

### 2. Client Setup

Next, set up and run the desktop client in a **separate terminal window**.

1.  **Navigate to the project root directory.**

2.  **Create and activate a separate virtual environment:**
    - On macOS/Linux:
      ```bash
      python3 -m venv client_venv
      source client_venv/bin/activate
      ```
    - On Windows:
      ```bash
      python -m venv client_venv
      .\client_venv\Scripts\activate
      ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r client/requirements.txt
    ```

4.  **Run the client:**
    From the **project root directory**, run the client as a module:
    ```bash
    python -m client.main
    ```

## How to Use

1.  **Start the Application:** Ensure the **server is running first**, then start the client.
2.  **Login/Register:**
    - The first time you run the application, you can use the default admin account for the "FabraForma" company:
      - **Email:** `admin@fabraforma_default.com`
      - **Password:** `password`
    - Alternatively, you can click "Register New Company" to create your own private company and admin user.
3.  **Configure Client Settings:**
    - After logging in, navigate to the **Settings** page.
    - The application will prompt you to select an **Image Input Folder**. This is the folder the application will monitor for new print summary images.
    - Fill in your company details for quotation generation.
4.  **Automated Logging:**
    - To log a print job, simply save the print summary image (from your slicer or printer) into the **Image Input Folder** you configured.
    - Go to the **Monitor** page in the client and click **"Start Monitoring"**.
    - The application will detect the new image, perform OCR, and open a **Verification** page for you to confirm the details.
    - Once confirmed, the job will be logged, and a detailed Excel file will be generated.
5.  **Generate a Quote from a 3D Model:**
    - Go to the **Quotation** page.
    - Click **"Upload STL for Quoting..."**.
    - Select your 3D model file (`.stl` or `.3mf`).
    - Choose the appropriate slicer profiles for the printer, filament, and quality.
    - Click **"Get Quote"**. The application will call the server to slice the model and calculate the COGS.
    - The calculated part will be added to your quotation list.
    - Fill in the customer details, set your profit margin, and click **"Generate Quotation PDF"**.