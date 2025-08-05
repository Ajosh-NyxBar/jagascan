'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield } from 'lucide-react';

interface NavbarProps {
  className?: string;
}

export default function Navbar({ className = '' }: NavbarProps) {
  const pathname = usePathname();

  const navItems = [
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/scan', label: 'New Scan' },
    { href: '/reports', label: 'Reports' }
  ];

  const isActive = (href: string) => pathname === href;

  return (
    <nav className={`border-b border-gray-700 bg-gray-900/50 backdrop-blur-sm ${className}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16 items-center">
          <Link href="/" className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-red-500" />
            <span className="text-xl font-bold text-white">JagaScan</span>
          </Link>
          
          <div className="hidden md:flex items-center space-x-8">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`transition-colors ${
                  isActive(item.href)
                    ? 'text-red-400 border-b-2 border-red-400 pb-1'
                    : 'text-white hover:text-red-400'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </div>

          {/* Mobile menu button - implement mobile menu as needed */}
          <div className="md:hidden">
            <button className="text-white hover:text-red-400">
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
