# BGMI Key Store

A Node.js web application for managing and selling BGMI serial keys.

## Features

- User authentication (login/register)
- Admin panel for managing keys
- User dashboard for purchasing keys
- Support for different key categories and durations
- Bulk key upload functionality
- Purchase history tracking

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd bgmi-key-store
```

2. Install dependencies:
```bash
npm install
```

3. Create necessary directories:
```bash
mkdir -p static/images static/css static/js
```

4. Place your background images in the `static/images` directory.

## Configuration

The application uses the following environment variables (you can create a `.env` file):

- `PORT` (default: 5000)
- `SESSION_SECRET` (default: 'your-secret-key-here')
- `ADMIN_USERNAME` (default: 'admin')
- `ADMIN_PASSWORD` (default: 'admin123')

## Running the Application

1. Start the server:
```bash
npm start
```

2. For development with auto-reload:
```bash
npm run dev
```

The application will be available at `http://localhost:5000`

## Default Admin Account

- Username: admin
- Password: admin123

## Directory Structure

```
bgmi-key-store/
├── app.js              # Main application file
├── models/             # Database models
├── views/             # EJS templates
│   ├── partials/     # Reusable template parts
│   └── ...
├── static/            # Static files
│   ├── css/          # Stylesheets
│   ├── js/           # Client-side JavaScript
│   └── images/       # Images
└── package.json      # Project dependencies
```

## License

MIT 