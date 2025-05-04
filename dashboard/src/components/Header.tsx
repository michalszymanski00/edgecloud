// src/components/Header.tsx
'use client';

import { Bell, UserCircle2, LogOut } from 'lucide-react';
import { useState } from 'react';

export function Header() {
  const [isUserMenuOpen, setUserMenuOpen] = useState(false);

  const toggleUserMenu = () => {
    setUserMenuOpen((prev) => !prev);
  };

  return (
    <header className="flex items-center justify-between bg-white px-6 py-4 shadow">
      <div className="flex-1">
        {/* You can put a breadcrumb or page title here */}
      </div>
      <div className="flex items-center space-x-4">
        {/* Notifications Button */}
        <button aria-label="Notifications" className="relative">
          <Bell size={20} />
          <span className="absolute top-0 right-0 inline-block h-2 w-2 bg-red-500 rounded-full"></span>
        </button>

        {/* User Menu */}
        <div className="relative">
          <button
            aria-label="User menu"
            onClick={toggleUserMenu}
            className="flex items-center space-x-2"
          >
            <UserCircle2 size={24} />
          </button>

          {/* Dropdown Menu */}
          {isUserMenuOpen && (
            <div className="absolute right-0 mt-2 w-48 bg-white shadow-lg rounded-lg">
              <ul className="space-y-2 p-2 text-gray-700">
                <li>
                  <button className="flex items-center space-x-2 w-full px-4 py-2 text-sm hover:bg-gray-200 rounded-md">
                    <LogOut size={16} />
                    <span>Logout</span>
                  </button>
                </li>
                {/* Other user menu items can go here */}
              </ul>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
