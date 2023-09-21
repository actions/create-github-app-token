const { main } = require('../lib/main');
const { createAppAuth } = require('@octokit/auth-app');
const { request } = require('@octokit/request');

describe('main', () => {
  let core;
  let createAppAuthMock;
  let requestMock;

  beforeEach(() => {
    core = {
      setSecret: jest.fn(),
      setOutput: jest.fn(),
      saveState: jest.fn(),
    };
    createAppAuthMock = jest.fn();
    requestMock = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should create an installation token for all repositories in the org', async () => {
    // Arrange
    const appId = '123';
    const privateKey = 'private-key';
    const org = 'my-org';
    const repositories = '';
    const installationId = 456;
    const token = 'installation-token';
    const createAppAuthResponse = jest.fn().mockResolvedValueOnce({ token });
    const requestResponse = jest.fn().mockResolvedValueOnce({ data: { id: installationId } });
    createAppAuthMock.mockReturnValueOnce(createAppAuthResponse);
    requestMock.mockReturnValueOnce(requestResponse);

    // Act
    await main(appId, privateKey, org, repositories, core, createAppAuthMock, requestMock);

    // Assert
    expect(createAppAuthMock).toHaveBeenCalledWith({
      appId,
      privateKey,
      request,
    });
    expect(requestMock).toHaveBeenCalledWith('GET /orgs/{org}/installation', {
      org,
      headers: {
        authorization: `bearer ${token}`,
      },
    });
    expect(createAppAuthResponse).toHaveBeenCalledWith({
      type: 'installation',
      installationId,
    });
    expect(core.setSecret).toHaveBeenCalledWith(token);
    expect(core.setOutput).toHaveBeenCalledWith('token', token);
    expect(core.saveState).toHaveBeenCalledWith('token', token);
  });

  it('should create an installation token for specified repositories in the org', async () => {
    // Arrange
    const appId = '123';
    const privateKey = 'private-key';
    const org = 'my-org';
    const repositories = 'repo1, repo2';
    const installationId = 456;
    const token = 'installation-token';
    const createAppAuthResponse = jest.fn().mockResolvedValueOnce({ token });
    const requestResponse = jest.fn().mockResolvedValueOnce({ data: { id: installationId } });
    createAppAuthMock.mockReturnValueOnce(createAppAuthResponse);
    requestMock.mockReturnValueOnce(requestResponse);

    // Act
    await main(appId, privateKey, org, repositories, core, createAppAuthMock, requestMock);

    // Assert
    expect(createAppAuthMock).toHaveBeenCalledWith({
      appId,
      privateKey,
      request,
    });
    expect(requestMock).toHaveBeenCalledWith('GET /orgs/{org}/installation', {
      org,
      headers: {
        authorization: `bearer ${token}`,
      },
    });
    expect(createAppAuthResponse).toHaveBeenCalledWith({
      type: 'installation',
      installationId,
      repositoryNames: ['repo1', 'repo2'],
    });
    expect(core.setSecret).toHaveBeenCalledWith(token);
    expect(core.setOutput).toHaveBeenCalledWith('token', token);
    expect(core.saveState).toHaveBeenCalledWith('token', token);
  });
});