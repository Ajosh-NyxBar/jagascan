import { AlertTriangle, CheckCircle, Info, XCircle } from 'lucide-react';

interface AlertProps {
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  className?: string;
}

export default function Alert({ type, title, message, className = '' }: AlertProps) {
  const getAlertStyles = () => {
    switch (type) {
      case 'success':
        return {
          container: 'bg-green-900/20 border-green-700 text-green-100',
          icon: <CheckCircle className="h-5 w-5 text-green-500" />,
          titleColor: 'text-green-400'
        };
      case 'error':
        return {
          container: 'bg-red-900/20 border-red-700 text-red-100',
          icon: <XCircle className="h-5 w-5 text-red-500" />,
          titleColor: 'text-red-400'
        };
      case 'warning':
        return {
          container: 'bg-yellow-900/20 border-yellow-700 text-yellow-100',
          icon: <AlertTriangle className="h-5 w-5 text-yellow-500" />,
          titleColor: 'text-yellow-400'
        };
      case 'info':
        return {
          container: 'bg-blue-900/20 border-blue-700 text-blue-100',
          icon: <Info className="h-5 w-5 text-blue-500" />,
          titleColor: 'text-blue-400'
        };
      default:
        return {
          container: 'bg-gray-900/20 border-gray-700 text-gray-100',
          icon: <Info className="h-5 w-5 text-gray-500" />,
          titleColor: 'text-gray-400'
        };
    }
  };

  const styles = getAlertStyles();

  return (
    <div className={`border rounded-lg p-4 ${styles.container} ${className}`}>
      <div className="flex items-start space-x-3">
        <div className="flex-shrink-0">
          {styles.icon}
        </div>
        <div className="flex-1">
          {title && (
            <h4 className={`font-semibold mb-1 ${styles.titleColor}`}>
              {title}
            </h4>
          )}
          <p className="text-sm">{message}</p>
        </div>
      </div>
    </div>
  );
}
