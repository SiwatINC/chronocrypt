import { AccessControlPolicy } from '../types/index';

export function createAllowAllPolicy(): AccessControlPolicy {
  return {
    id: 'allow-all',
    name: 'Allow All',
    evaluate: async () => true,
    priority: -1000
  };
}
