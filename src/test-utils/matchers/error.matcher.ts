import type { MatcherFunction } from 'expect';
import { diff } from 'jest-diff';
import { printExpected, printReceived } from 'jest-matcher-utils';
import { isDeepStrictEqual } from 'util';
import { SDJWTVCError } from '../../errors';

/**
 * Custom matcher for SDJWTVCError to make sure type and extra information is always as expected
 */
export const toThrowSDJWTVCError: MatcherFunction<[exception: unknown]> = (actual: any, expected: SDJWTVCError) => {
  let exception = null;

  if (typeof actual === 'function') {
    try {
      actual();
    } catch (e) {
      exception = e;
    }
  } else {
    exception = actual;
  }

  if (exception === null) {
    return {
      message: () => `expected to throw a SDJWTVCError but nothing was thrown`,
      pass: false,
    };
  }

  if (!(exception instanceof SDJWTVCError)) {
    return {
      message: () =>
        `expected ${printReceived(exception.constructor.name)} to be an instance of ${printExpected('SDJWTVCError')}`,
      pass: false,
    };
  }

  if (expected.getErrorType() !== exception.getErrorType()) {
    return {
      message: () =>
        `expected exception.getErrorType() ${printReceived(
          exception.getErrorType(),
        )} to be equal to ${printExpected(expected.getErrorType())}`,
      pass: false,
    };
  }

  const expectedExtraInfo = expected.getExtraInfo();
  const actualExtraInfo = exception.getExtraInfo();

  if (!isDeepStrictEqual(expectedExtraInfo, actualExtraInfo)) {
    return {
      message: () =>
        `exception.getExtraInfo() does not match expected value\n${diff(expectedExtraInfo, actualExtraInfo)}`,
      pass: false,
    };
  }

  return {
    message: () => null,
    pass: true,
  };
};

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace jest {
    interface Matchers<R> {
      toThrowSDJWTVCError(exception: SDJWTVCError): R;
    }
  }
}
