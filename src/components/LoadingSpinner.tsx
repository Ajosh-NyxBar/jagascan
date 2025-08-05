interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  color?: 'red' | 'blue' | 'green' | 'yellow' | 'white';
  className?: string;
}

export default function LoadingSpinner({ 
  size = 'md', 
  color = 'red', 
  className = '' 
}: LoadingSpinnerProps) {
  const getSizeClasses = () => {
    switch (size) {
      case 'sm': return 'h-4 w-4';
      case 'md': return 'h-6 w-6';
      case 'lg': return 'h-8 w-8';
      default: return 'h-6 w-6';
    }
  };

  const getColorClasses = () => {
    switch (color) {
      case 'red': return 'border-red-500';
      case 'blue': return 'border-blue-500';
      case 'green': return 'border-green-500';
      case 'yellow': return 'border-yellow-500';
      case 'white': return 'border-white';
      default: return 'border-red-500';
    }
  };

  return (
    <div 
      className={`animate-spin rounded-full border-2 border-t-transparent ${getSizeClasses()} ${getColorClasses()} ${className}`}
    />
  );
}
