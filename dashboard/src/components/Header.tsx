import { Bell, UserCircle2 } from 'lucide-react';

export function Header() {
  return (
    <header className="flex items-center justify-between bg-white px-6 py-4 shadow">
      <div className="flex-1">
        {/* You can put a breadcrumb or page title here */}
      </div>
      <div className="flex items-center space-x-4">
        <button aria-label="Notifications">
          <Bell size={20} />
        </button>
        <button aria-label="User menu">
          <UserCircle2 size={24} />
        </button>
      </div>
    </header>
  );
}
