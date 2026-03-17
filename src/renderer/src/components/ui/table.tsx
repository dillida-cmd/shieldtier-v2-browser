import * as React from 'react';
import { cn } from '../../lib/utils';

interface TableProps extends React.HTMLAttributes<HTMLTableElement> {
  striped?: boolean;
  compact?: boolean;
}

const Table = React.forwardRef<HTMLTableElement, TableProps>(
  ({ className, striped, compact, ...props }, ref) => (
    <div className="relative w-full overflow-auto">
      <table
        ref={ref}
        data-striped={striped || undefined}
        data-compact={compact || undefined}
        className={cn('w-full caption-bottom text-sm', className)}
        {...props}
      />
    </div>
  ),
);
Table.displayName = 'Table';

const TableHeader = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead
    ref={ref}
    className={cn('[&_tr]:border-b [&_tr]:border-[color:var(--st-border)]', className)}
    {...props}
  />
));
TableHeader.displayName = 'TableHeader';

const TableBody = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody
    ref={ref}
    className={cn('[&_tr:last-child]:border-0', className)}
    {...props}
  />
));
TableBody.displayName = 'TableBody';

const TableFooter = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tfoot
    ref={ref}
    className={cn(
      'border-t border-[color:var(--st-border)] font-medium',
      className,
    )}
    {...props}
  />
));
TableFooter.displayName = 'TableFooter';

const TableRow = React.forwardRef<
  HTMLTableRowElement,
  React.HTMLAttributes<HTMLTableRowElement>
>(({ className, ...props }, ref) => (
  <tr
    ref={ref}
    className={cn(
      'border-b border-[color:var(--st-border-subtle)] transition-colors hover:bg-[color:var(--st-accent-dim)] data-[state=selected]:bg-[color:var(--st-accent-dim)] [table[data-striped]_&]:odd:bg-[color:var(--st-accent-dim)]/50',
      className,
    )}
    {...props}
  />
));
TableRow.displayName = 'TableRow';

const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      'h-9 px-3 py-2 text-left align-middle text-xs font-medium uppercase tracking-wider text-[color:var(--st-text-muted)] [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px] [table[data-compact]_&]:h-7 [table[data-compact]_&]:px-2 [table[data-compact]_&]:py-1',
      className,
    )}
    {...props}
  />
));
TableHead.displayName = 'TableHead';

const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <td
    ref={ref}
    className={cn(
      'px-3 py-2 align-middle text-[color:var(--st-text-primary)] [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px] [table[data-compact]_&]:px-2 [table[data-compact]_&]:py-1',
      className,
    )}
    {...props}
  />
));
TableCell.displayName = 'TableCell';

const TableCaption = React.forwardRef<
  HTMLTableCaptionElement,
  React.HTMLAttributes<HTMLTableCaptionElement>
>(({ className, ...props }, ref) => (
  <caption
    ref={ref}
    className={cn(
      'mt-4 text-sm text-[color:var(--st-text-muted)]',
      className,
    )}
    {...props}
  />
));
TableCaption.displayName = 'TableCaption';

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
};
