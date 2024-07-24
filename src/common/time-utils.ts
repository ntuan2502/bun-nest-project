// src/utils/time-utils.ts

import { format, toZonedTime } from 'date-fns-tz';

// Múi giờ GMT+7
const TIME_ZONE = 'Asia/Ho_Chi_Minh';

/**
 * Chuyển đổi thời gian UTC sang múi giờ GMT+7 và định dạng theo chuỗi.
 * @param date - Thời gian UTC cần chuyển đổi.
 * @returns Thời gian đã định dạng theo múi giờ GMT+7.
 */
export function convertToTimeZone(date: Date): string {
  const zonedDate = toZonedTime(date, TIME_ZONE);
  return format(zonedDate, 'dd/MM/yyyy HH:mm:ssXXX', { timeZone: TIME_ZONE });
}
