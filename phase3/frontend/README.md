# Multi-Agent CTF System Frontend

Modern, professional frontend built with Next.js 14, TypeScript, Tailwind CSS, and shadcn/ui components.

## Features

- **Modern Design**: Clean, professional interface using shadcn/ui components
- **Real-time Dashboard**: Live metrics and system monitoring
- **Challenge Execution**: Interactive interface for submitting CTF challenges
- **Responsive Layout**: Works on desktop, tablet, and mobile devices
- **Type Safety**: Full TypeScript integration with API types
- **Performance**: Optimized with Next.js 14 and modern React patterns

## Tech Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Components**: shadcn/ui (Radix UI primitives)
- **Icons**: Lucide React
- **HTTP Client**: Axios with SWR for data fetching
- **Build Tool**: Next.js built-in bundler

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

1. **Install dependencies**:
```bash
cd phase3/frontend
npm install
```

2. **Start development server**:
```bash
npm run dev
```

3. **Open browser**:
Navigate to [http://localhost:3000](http://localhost:3000)

### Environment Variables

Create a `.env.local` file:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── layout.tsx         # Root layout
│   ├── page.tsx           # Dashboard page
│   ├── challenge/         # Challenge execution page
│   └── globals.css        # Global styles
├── components/            # React components
│   ├── ui/               # shadcn/ui base components
│   ├── DashboardLayout.tsx
│   ├── MetricsCard.tsx
│   ├── SystemStatus.tsx
│   └── RecentActivity.tsx
├── lib/                  # Utilities
│   ├── api.ts           # API client
│   └── utils.ts         # Utility functions
└── types/               # TypeScript types
    └── api.ts          # API type definitions
```

## Components

### UI Components (shadcn/ui)

- **Button**: Versatile button component with variants
- **Card**: Container component for content sections
- **Badge**: Status and category indicators
- **Tabs**: Tabbed navigation interface
- **Input/Textarea**: Form input components
- **Label**: Form labels with accessibility

### Custom Components

- **DashboardLayout**: Main application layout with sidebar
- **MetricsCard**: Displays key performance metrics
- **SystemStatus**: Shows system and agent status
- **RecentActivity**: Lists recent challenge executions

## Pages

### Dashboard (`/`)
- System overview and key metrics
- Real-time status monitoring
- Performance analytics
- Recent activity feed

### Challenge Execution (`/challenge`)
- Interactive challenge submission form
- Multi-file upload support
- Real-time execution results
- Detailed performance metrics

## API Integration

The frontend communicates with the backend through a typed API client:

```typescript
import { api } from '@/lib/api';

// Get system metrics
const metrics = await api.getMetrics(7);

// Execute challenge
const result = await api.solveChallenge({
  description: "RSA challenge",
  files: [{ name: "challenge.py", content: "..." }]
});
```

## Styling

### Tailwind CSS

The project uses Tailwind CSS with a custom configuration:

- **Design System**: Consistent spacing, colors, and typography
- **Dark Mode**: Ready for dark mode implementation
- **Responsive**: Mobile-first responsive design
- **Custom Colors**: Brand-specific color palette

### shadcn/ui Theme

CSS custom properties for consistent theming:

```css
:root {
  --background: 0 0% 100%;
  --foreground: 222.2 84% 4.9%;
  --primary: 221.2 83.2% 53.3%;
  --secondary: 210 40% 96%;
  /* ... */
}
```

## Development

### Available Scripts

```bash
# Development server
npm run dev

# Production build
npm run build

# Start production server
npm start

# Linting
npm run lint

# Type checking
npm run type-check
```

### Code Quality

- **TypeScript**: Strict type checking enabled
- **ESLint**: Code linting with Next.js rules
- **Prettier**: Code formatting (recommended)

## Deployment

### Build for Production

```bash
npm run build
```

### Environment Variables

For production, set:

```env
NEXT_PUBLIC_API_URL=https://your-api-domain.com
```

### Deployment Options

- **Vercel**: Optimal for Next.js applications
- **Netlify**: Static site deployment
- **Docker**: Containerized deployment
- **Traditional Hosting**: Build and serve static files

## Performance

### Optimizations

- **Code Splitting**: Automatic with Next.js App Router
- **Image Optimization**: Next.js Image component
- **Bundle Analysis**: Use `@next/bundle-analyzer`
- **Caching**: SWR for API response caching

### Monitoring

- **Core Web Vitals**: Monitored by Next.js
- **Performance**: Browser DevTools
- **Bundle Size**: Keep track of bundle growth

## Accessibility

- **Semantic HTML**: Proper HTML structure
- **ARIA Labels**: Screen reader support
- **Keyboard Navigation**: Full keyboard accessibility
- **Color Contrast**: WCAG compliant colors

## Browser Support

- **Modern Browsers**: Chrome, Firefox, Safari, Edge
- **Mobile**: iOS Safari, Chrome Mobile
- **Minimum**: ES2018 support required

## Contributing

1. Follow TypeScript best practices
2. Use shadcn/ui components when possible
3. Maintain responsive design
4. Add proper TypeScript types
5. Test on multiple screen sizes

## Troubleshooting

### Common Issues

1. **API Connection**: Check `NEXT_PUBLIC_API_URL`
2. **Build Errors**: Run `npm run type-check`
3. **Styling Issues**: Check Tailwind CSS classes
4. **Component Errors**: Verify shadcn/ui imports

### Debug Mode

Enable debug logging:

```typescript
// In api.ts
console.log('API Request:', config);
```

---

**Status**: ✅ Production Ready  
**Version**: 3.0.0  
**Last Updated**: 2025-10-26