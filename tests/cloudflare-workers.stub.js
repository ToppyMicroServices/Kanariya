// Unit fixture only. Native named-entrypoint behavior is checked in workerd.
export class WorkerEntrypoint {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
}
