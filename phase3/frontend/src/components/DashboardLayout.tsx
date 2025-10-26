'use client';

import { ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { 
  Home, 
  BarChart3, 
  Settings, 
  FileText,
  Play,
  AlertTriangle,
  Activity,
  Zap
} from 'lucide-react';

interface DashboardLayoutProps {
  children: ReactNode;
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Execute Challenge', href: '/challenge', icon: Play },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Auto-Tuning', href: '/tuning', icon: Settings },
  { name: 'History', href: '/history', icon: FileText },
  { name: 'System Health', href: '/health', icon: Activity },
];

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const pathname = usePathname();

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <div className="hidden md:flex md:w-64 md:flex-col">
        <div className="flex flex-col flex-grow border-r bg-card">
          {/* Logo */}
          <div className="flex items-center h-16 px-6 border-b">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-8 h-8 bg-primary rounded-lg">
                <Zap className="w-5 h-5 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-lg font-semibold">Multi-Agent CTF</h1>
                <p className="text-xs text-muted-foreground">Phase 3.0</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2">
            {navigation.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    "flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors",
                    isActive
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* Status Footer */}
          <div className="p-4 border-t">
            <div className="flex items-center space-x-2 text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-muted-foreground">System Active</span>
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              Version 3.0.0
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Mobile header */}
        <div className="md:hidden bg-card border-b px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-8 h-8 bg-primary rounded-lg">
                <Zap className="w-5 h-5 text-primary-foreground" />
              </div>
              <h1 className="text-lg font-semibold">Multi-Agent CTF</h1>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <div className="container mx-auto py-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}