# SSTP Proxy

A lightweight and modern proxy for the **SSTP** (Secure Socket Tunneling Protocol), built with **Next.js**, **TypeScript**, and **Drizzle ORM**.

## ✨ Features

- SSTP proxy implementation with secure connection support
- Web-based interface powered by Next.js (App Router)
- Database management via Drizzle ORM
- Modular structure with separate `client` and `src` directories
- Easy configuration through environment variables
- Automated CI/CD workflow for releases (`.github/workflows`)

## 🧱 Prerequisites

- **Node.js** v18 or higher
- **npm**, **yarn**, or **pnpm**
- (Optional) A Drizzle-compatible database (e.g., PostgreSQL or SQLite)

## 🚀 Installation & Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/FossilizedProgrammer/sstp-proxy.git
   cd sstp-proxy
   ```

2. Install dependencies:

   ```bash
   npm install
   # or
   yarn install
   # or
   pnpm install
   ```

3. Create an environment file (if needed):

   ```bash
   cp .env.example .env
   ```

   Then configure the required variables (database URL, server port, etc.) in `.env`.

4. Push the database schema (if using Drizzle):

   ```bash
   npx drizzle-kit push
   ```

5. Run the project in development mode:

   ```bash
   npm run dev
   ```

   Then open [http://localhost:3000](http://localhost:3000) in your browser.

## 🏗️ Project Structure

```
sstp-proxy/
├── .github/workflows/   # CI/CD workflows
├── client/              # Client-side code
├── src/                 # Main source (Next.js)
├── drizzle.config.json  # Drizzle ORM configuration
├── eslint.config.mjs    # ESLint configuration
├── next.config.ts       # Next.js configuration
├── package.json         # Dependencies and scripts
├── postcss.config.mjs   # PostCSS configuration
└── tsconfig.json        # TypeScript configuration
```

## 🛠️ Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start the project in development mode |
| `npm run build` | Build the production version |
| `npm run start` | Run the production build |
| `npm run lint` | Lint the code with ESLint |

> Note: The exact list of scripts may vary depending on your `package.json`.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the project.
2. Create a new branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## 📬 Contact

- **Author:** [FossilizedProgrammer](https://github.com/FossilizedProgrammer)
- **Project Link:** [https://github.com/FossilizedProgrammer/sstp-proxy](https://github.com/FossilizedProgrammer/sstp-proxy)
