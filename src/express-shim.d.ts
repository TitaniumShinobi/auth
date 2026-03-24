declare module 'express' {
  export type Request = any;
  export type Response = any;
  export type NextFunction = any;
  export type Express = any;
  export type RequestHandler = (...args: any[]) => any;

  type ExpressFactory = {
    (): Express;
    Router: () => any;
    json: (options?: any) => any;
  };

  const express: ExpressFactory;
  export default express;
}
