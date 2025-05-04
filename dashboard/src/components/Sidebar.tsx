'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Home, Cpu, Settings, Bell, FileText } from 'lucide-react';

const navItems = [
  { href: '/', label: 'Dashboard', icon: <Home size={18} /> },
  { href: '/devices', label: 'Devices', icon: <Cpu size={18} /> },
  { href: '/workflows', label: 'Workflows', icon: <FileText size={18} /> }, // Add this line
  { href: '/alerts', label: 'Alerts', icon: <Bell size={18} /> },
  { href: '/settings', label: 'Settings', icon: <Settings size={18} /> },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-64 h-screen bg-gray-800 text-gray-100 flex flex-col">
      <div className="p-4 text-2xl font-bold">EdgeCloud</div>
      <nav className="flex-1 px-2 space-y-1">
        {navItems.map(({ href, label, icon }) => {
          const active = path === href;
          return (
            <Link
              key={href}
              href={href}
              className={`
                flex items-center px-3 py-2 rounded-md text-sm font-medium
                ${active ? 'bg-gray-700' : 'hover:bg-gray-700'}
              `}
            >
              <span className="mr-2">{icon}</span>
              {label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
