# Enhanced CTF Solver Frontend

Modern Next.js frontend for the Enhanced CTF Solver system with multi-agent AI capabilities.

## Features

- 🎯 **Challenge Solving Interface** - Submit and solve CTF challenges
- 📊 **Real-time System Status** - Monitor backend components and health
- 📈 **Statistics Dashboard** - View performance metrics and analytics
- 🤖 **Multi-Agent Integration** - Leverage BERT + RAG enhanced system
- 🎨 **Modern UI/UX** - Built with Tailwind CSS and Headless UI
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile
- ⚡ **Real-time Updates** - Live status and progress monitoring

## Tech Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **UI Components**: Headless UI + Custom Components
- **Icons**: Heroicons
- **HTTP Client**: Axios
- **Charts**: Recharts
- **Notifications**: React Hot Toast

## Quick Start

### Prerequisites

- Node.js 18+ 
- npm or yarn
- Backend API running on http://localhost:8000

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

### Environment Variables

Create a `.env.local` file:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Project Structure

```
src/
├── app/                    # Next.js App Router
│   ├── globals.css        # Global styles
│   ├── layout.tsx         # Root layout
│   └── page.tsx           # Home page
├── components/            # React components
│   └── ui/               # Reusable UI components
│       ├── Button.tsx
│       ├── Card.tsx
│       └── LoadingSpinner.tsx
├── hooks/                # Custom React hooks
│   └── useAPI.ts         # API interaction hooks
├── lib/                  # Utilities and configurations
│   └── api.ts           # API client and utilities
└── types/               # TypeScript type definitions
    └── api.ts           # API response types
```

## Key Components

### Challenge Solver
- Submit challenge descriptions and files
- Choose between enhanced and simple solving modes
- Real-time progress tracking
- Detailed result display with flags, strategies, and metrics

### System Status
- Live backend component health monitoring
- Capability overview
- Performance statistics
- Connection status indicators

### API Integration
- Automatic error handling and retry logic
- Type-safe API calls with TypeScript
- Real-time status updates
- File upload support

## API Endpoints Used

- `GET /api/status` - System health and capabilities
- `POST /api/solve` - Solve CTF challenges
- `POST /api/classify` - Classify challenge types
- `GET /api/statistics` - Performance metrics
- `GET /api/history` - Solve history
- `GET /api/rag/search` - Search writeups
- `POST /api/upload` - Upload challenge files

## Development

### Available Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run start        # Start production server
npm run lint         # Run ESLint
npm run type-check   # Run TypeScript checks
```

### Code Style

- TypeScript for type safety
- ESLint + Prettier for code formatting
- Tailwind CSS for styling
- Component-based architecture
- Custom hooks for state management

### Adding New Features

1. **New API Endpoint**: Add types to `src/types/api.ts` and functions to `src/lib/api.ts`
2. **New Component**: Create in `src/components/` with proper TypeScript types
3. **New Page**: Add to `src/app/` following App Router conventions
4. **New Hook**: Add to `src/hooks/` for reusable logic

## Deployment

### Vercel (Recommended)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Set environment variables in Vercel dashboard
NEXT_PUBLIC_API_URL=https://your-backend-url.com
```

### Docker

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
```

### Static Export

```bash
# Add to next.config.js
output: 'export'

# Build static files
npm run build
```

## Configuration

### API Configuration

The frontend automatically connects to the backend API. Configure the URL in:

- Development: `NEXT_PUBLIC_API_URL` in `.env.local`
- Production: Environment variables in your deployment platform

### Styling Customization

Modify `tailwind.config.js` to customize:
- Colors and themes
- Typography
- Spacing and sizing
- Component styles

### Feature Flags

Enable/disable features by modifying:
- Component visibility
- API endpoint usage
- UI elements

## Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Check if backend is running on correct port
   - Verify CORS settings in backend
   - Check network connectivity

2. **Build Errors**
   - Run `npm run type-check` to find TypeScript errors
   - Check for missing dependencies
   - Verify environment variables

3. **Styling Issues**
   - Clear browser cache
   - Check Tailwind CSS compilation
   - Verify component class names

### Debug Mode

Enable debug logging:

```typescript
// In src/lib/api.ts
const DEBUG = process.env.NODE_ENV === 'development';

if (DEBUG) {
  console.log('API Request:', request);
}
```

## Performance

### Optimization Features

- **Code Splitting**: Automatic with Next.js
- **Image Optimization**: Next.js Image component
- **Bundle Analysis**: `npm run analyze`
- **Caching**: API response caching
- **Lazy Loading**: Component lazy loading

### Monitoring

- Real-time performance metrics
- API response time tracking
- Error rate monitoring
- User interaction analytics

## Security

### Best Practices

- Environment variables for sensitive data
- Input validation and sanitization
- HTTPS in production
- Content Security Policy headers
- XSS protection

### API Security

- CORS configuration
- Request rate limiting
- Authentication tokens (when implemented)
- Input validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Standards

- Follow TypeScript best practices
- Use meaningful component and variable names
- Add JSDoc comments for complex functions
- Maintain consistent code formatting
- Write responsive and accessible UI

## License

This project is part of the Enhanced CTF Solver system. See the main repository for license information.

## Support

For issues and questions:
- Check the troubleshooting section
- Review the API documentation
- Create an issue in the repository
- Check the backend logs for API errors