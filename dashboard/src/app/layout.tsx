import './globals.css';
import { Inter } from 'next/font/google';
import { Sidebar } from '../components/Sidebar';
import { Header }  from '../components/Header';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'EdgeCloud Control Plane',
  description: 'Manage your edge devices at scale',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <div className="flex-1 flex flex-col">
            <Header />
            <main className="flex-1 p-6 overflow-auto bg-gray-50">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
